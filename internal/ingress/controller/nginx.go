/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	proxyproto "github.com/armon/go-proxyproto"
	"github.com/eapache/channels"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/ingress-nginx/pkg/tcpproxy"

	adm_controller "k8s.io/ingress-nginx/internal/admission/controller"
	ngx_config "k8s.io/ingress-nginx/internal/ingress/controller/config"
	"k8s.io/ingress-nginx/internal/ingress/controller/process"
	"k8s.io/ingress-nginx/internal/ingress/controller/store"
	ngx_template "k8s.io/ingress-nginx/internal/ingress/controller/template"
	"k8s.io/ingress-nginx/internal/ingress/metric"
	"k8s.io/ingress-nginx/internal/ingress/status"
	ing_net "k8s.io/ingress-nginx/internal/net"
	"k8s.io/ingress-nginx/internal/net/dns"
	"k8s.io/ingress-nginx/internal/net/ssl"
	"k8s.io/ingress-nginx/internal/nginx"
	"k8s.io/ingress-nginx/internal/task"
	"k8s.io/ingress-nginx/pkg/apis/ingress"

	"k8s.io/ingress-nginx/pkg/util/file"
	utilingress "k8s.io/ingress-nginx/pkg/util/ingress"

	klog "k8s.io/klog/v2"
)

const (
	tempNginxPattern = "nginx-cfg"
	emptyUID         = "-1"
)

// NewNGINXController creates a new NGINX Ingress controller.
func NewNGINXController(config *Configuration, mc metric.Collector) *NGINXController {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{
		Interface: config.Client.CoreV1().Events(config.Namespace),
	})

	// 读取 resulv.conf 文件，获取 dns server 地址集合
	h, err := dns.GetSystemNameServers()
	if err != nil {
		klog.Warningf("Error reading system nameservers: %v", err)
	}

	n := &NGINXController{
		isIPV6Enabled: ing_net.IsIPv6Enabled(),

		resolver:        h,
		cfg:             config,
		syncRateLimiter: flowcontrol.NewTokenBucketRateLimiter(config.SyncRateLimit, 1),

		recorder: eventBroadcaster.NewRecorder(scheme.Scheme, apiv1.EventSource{
			Component: "nginx-ingress-controller",
		}),

		stopCh: make(chan struct{}),
		// informer 注册 eventHandler 会往这个 chan 发送事件.
		updateCh: channels.NewRingChannel(1024),

		ngxErrCh: make(chan error),

		stopLock: &sync.Mutex{},

		runningConfig: new(ingress.Configuration),

		Proxy: &tcpproxy.TCPProxy{},

		metricCollector: mc,

		command: NewNginxCommand(),
	}

	if n.cfg.ValidationWebhook != "" {
		n.validationWebhookServer = &http.Server{
			Addr: config.ValidationWebhook,
			//G112 (CWE-400): Potential Slowloris Attack
			ReadHeaderTimeout: 10 * time.Second,
			Handler:           adm_controller.NewAdmissionControllerServer(&adm_controller.IngressAdmission{Checker: n}),
			TLSConfig:         ssl.NewTLSListener(n.cfg.ValidationWebhookCertPath, n.cfg.ValidationWebhookKeyPath).TLSConfig(),
			// disable http/2
			// https://github.com/kubernetes/kubernetes/issues/80313
			// https://github.com/kubernetes/ingress-nginx/issues/6323#issuecomment-737239159
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
	}

	// 实例化 store 对象, 可以把 store 想成一个有各种数据的缓存的存储, 内部也有 informer.
	n.store = store.New(
		config.Namespace,
		config.WatchNamespaceSelector,
		config.ConfigMapName,
		config.TCPConfigMapName,
		config.UDPConfigMapName,
		config.DefaultSSLCertificate,
		config.ResyncPeriod,
		config.Client,
		n.updateCh, // 把实例化的 updateCh 传进去
		config.DisableCatchAll,
		config.DeepInspector,
		config.IngressClassConfiguration,
		config.DisableSyncEvents)
	// 实例化 queue, 并且在 queue里注册了回调方法, syncIngress 是 nginx ingress controller 最核心的同步方法.
	n.syncQueue = task.NewTaskQueue(n.syncIngress)

	if config.UpdateStatus {
		n.syncStatus = status.NewStatusSyncer(status.Config{
			Client:                 config.Client,
			PublishService:         config.PublishService,
			PublishStatusAddress:   config.PublishStatusAddress,
			IngressLister:          n.store,
			UpdateStatusOnShutdown: config.UpdateStatusOnShutdown,
			UseNodeInternalIP:      config.UseNodeInternalIP,
		})
	} else {
		klog.Warning("Update of Ingress status is disabled (flag --update-status)")
	}

	// 用在 inotify 文件监听的回调方法
	onTemplateChange := func() {
		// 从 `/etc/nginx/template/nginx.tmpl` 读取预设的模板, 然后进行解析生成 template 对象.
		template, err := ngx_template.NewTemplate(nginx.TemplatePath)
		if err != nil {
			// this error is different from the rest because it must be clear why nginx is not working
			klog.ErrorS(err, "Error loading new template")
			return
		}

		n.t = template
		klog.InfoS("New NGINX configuration template loaded")
		// 向 queue 传递事件, 平滑热加载 nginx 配置
		n.syncQueue.EnqueueTask(task.GetDummyObject("template-change"))
	}

	// 从 `/etc/nginx/template/nginx.tmpl` 读取预设的模板, 然后进行解析生成 template 对象.
	ngxTpl, err := ngx_template.NewTemplate(nginx.TemplatePath)
	if err != nil {
		klog.Fatalf("Invalid NGINX configuration template: %v", err)
	}

	n.t = ngxTpl

	// 使用 inotify 机制异步监听 nginx.tmpl 模板文件, 当模板文件发生变更时, 则回调 onTemplateChange 方法, 重新读取模板并构建模板对象, 然后同步配置
	_, err = file.NewFileWatcher(nginx.TemplatePath, onTemplateChange)
	if err != nil {
		klog.Fatalf("Error creating file watcher for %v: %v", nginx.TemplatePath, err)
	}

	// 获取 geoip 目录下的相关文件, v4.4.2 里当前就只有三个文件, 分别是 geoip.dat, geoIPASNum.dat, geoLiteCity.dat 数据文件.
	filesToWatch := []string{}
	err = filepath.Walk("/etc/nginx/geoip/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		filesToWatch = append(filesToWatch, path)
		return nil
	})

	if err != nil {
		klog.Fatalf("Error creating file watchers: %v", err)
	}

	for _, f := range filesToWatch {
		// 异步监听 geoip dat 数据文件, 当发生增删改时, 重新平滑热加载 nginx 配置.
		_, err = file.NewFileWatcher(f, func() {
			klog.InfoS("File changed detected. Reloading NGINX", "path", f)
			n.syncQueue.EnqueueTask(task.GetDummyObject("file-change"))
		})
		if err != nil {
			klog.Fatalf("Error creating file watcher for %v: %v", f, err)
		}
	}

	return n
}

// NGINXController describes a NGINX Ingress controller.
type NGINXController struct {
	cfg *Configuration

	recorder record.EventRecorder

	syncQueue *task.Queue

	syncStatus status.Syncer

	syncRateLimiter flowcontrol.RateLimiter

	// stopLock is used to enforce that only a single call to Stop send at
	// a given time. We allow stopping through an HTTP endpoint and
	// allowing concurrent stoppers leads to stack traces.
	stopLock *sync.Mutex

	stopCh   chan struct{}
	updateCh *channels.RingChannel

	// ngxErrCh is used to detect errors with the NGINX processes
	ngxErrCh chan error

	// runningConfig contains the running configuration in the Backend
	runningConfig *ingress.Configuration

	t ngx_template.Writer

	resolver []net.IP

	isIPV6Enabled bool

	isShuttingDown bool

	Proxy *tcpproxy.TCPProxy

	store store.Storer

	metricCollector    metric.Collector
	admissionCollector metric.Collector

	validationWebhookServer *http.Server

	command NginxExecTester
}

// Start starts a new NGINX master process running in the foreground.
//
//	服务启动的入口
func (n *NGINXController) Start() {
	klog.InfoS("Starting NGINX Ingress controller")
	// 内部启动 informer 监听并维护各资源的本地缓存
	n.store.Run(n.stopCh)

	// we need to use the defined ingress class to allow multiple leaders
	// in order to update information about ingress status
	// TODO: For now, as the the IngressClass logics has changed, is up to the
	// cluster admin to create different Leader Election IDs.
	// Should revisit this in a future
	electionID := n.cfg.ElectionID

	// 进行选举, 只有主实例才可以执行状态同步的更新的逻辑
	setupLeaderElection(&leaderElectionConfig{
		Client:     n.cfg.Client,
		ElectionID: electionID,
		OnStartedLeading: func(stopCh chan struct{}) {
			if n.syncStatus != nil {
				// 开启状态的同步更新
				go n.syncStatus.Run(stopCh)
			}

			n.metricCollector.OnStartedLeading(electionID)
			// manually update SSL expiration metrics
			// (to not wait for a reload)
			n.metricCollector.SetSSLExpireTime(n.runningConfig.Servers)
			n.metricCollector.SetSSLInfo(n.runningConfig.Servers)
		},
		OnStoppedLeading: func() {
			n.metricCollector.OnStoppedLeading(electionID)
		},
	})

	// 配置进程组, 使用 cmd 创建的程序都所属相同的 pgid 组id,
	// 这样杀掉进程时可以按照进程组杀, 避免有遗漏的进程.
	cmd := n.command.ExecCommand()

	// put NGINX in another process group to prevent it
	// to receive signals meant for the controller
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	// 加载 ssl proxy
	if n.cfg.EnableSSLPassthrough {
		n.setupSSLProxy()
	}

	klog.InfoS("Starting NGINX process")
	// 启动 nginx 进程, 指定配置为 `/etc/nginx/nginx.conf`.
	n.start(cmd)

	// 启动 syncQueue 里 run 方法, 该方法内部会从队列中读取任务,
	// 并调用 syncIngress 来同步 nginx 配置.
	go n.syncQueue.Run(time.Second, n.stopCh)
	// force initial sync
	// 前面 nginx 启动使用时, 只是使用了默认的 nginx.conf, 里面几乎没什么东西,
	// 这里通过主动传任务到 syncqueue, 然后 syncqueue 利用 syncIngress 来同步配置并完成热加载
	n.syncQueue.EnqueueTask(task.GetDummyObject("initial-sync"))

	// In case of error the temporal configuration file will
	// be available up to five minutes after the error
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			// 启动一个异步 gc 协程, 清理 nginx 临时文件, 临时文件的名字前缀有 `nginx-cfg` 字符串,
			// 当满足临时文件特征, 且更改超过5分钟则删除该临时文件
			err := cleanTempNginxCfg()
			if err != nil {
				klog.ErrorS(err, "Unexpected error removing temporal configuration files")
			}
		}
	}()

	if n.validationWebhookServer != nil {
		klog.InfoS("Starting validation webhook", "address", n.validationWebhookServer.Addr,
			"certPath", n.cfg.ValidationWebhookCertPath, "keyPath", n.cfg.ValidationWebhookKeyPath)
		go func() {
			klog.ErrorS(n.validationWebhookServer.ListenAndServeTLS("", ""), "Error listening for TLS connections")
		}()
	}

	for {
		select {
		case err := <-n.ngxErrCh:
			if n.isShuttingDown {
				return
			}

			// if the nginx master process dies, the workers continue to process requests
			// until the failure of the configured livenessProbe and restart of the pod.
			if process.IsRespawnIfRequired(err) {
				return
			}

		case event := <-n.updateCh.Out():
			if n.isShuttingDown {
				break
			}
			// 从 informer 拿到更改事件
			if evt, ok := event.(store.Event); ok {
				klog.V(3).InfoS("Event received", "type", evt.Type, "object", evt.Obj)
				if evt.Type == store.ConfigurationEvent {
					// TODO: is this necessary? Consider removing this special case
					n.syncQueue.EnqueueTask(task.GetDummyObject("configmap-change"))
					continue
				}
				// 同上, 只是任务可跳过.
				n.syncQueue.EnqueueSkippableTask(evt.Obj)
			} else {
				klog.Warningf("Unexpected event type received %T", event)
			}
		case <-n.stopCh:
			return
		}
	}
}

// Stop gracefully stops the NGINX master process.
func (n *NGINXController) Stop() error {
	n.isShuttingDown = true

	n.stopLock.Lock()
	defer n.stopLock.Unlock()

	if n.syncQueue.IsShuttingDown() {
		return fmt.Errorf("shutdown already in progress")
	}

	time.Sleep(time.Duration(n.cfg.ShutdownGracePeriod) * time.Second)

	klog.InfoS("Shutting down controller queues")
	close(n.stopCh)
	go n.syncQueue.Shutdown()
	if n.syncStatus != nil {
		n.syncStatus.Shutdown()
	}

	if n.validationWebhookServer != nil {
		klog.InfoS("Stopping admission controller")
		err := n.validationWebhookServer.Close()
		if err != nil {
			return err
		}
	}

	// send stop signal to NGINX
	klog.InfoS("Stopping NGINX process")
	cmd := n.command.ExecCommand("-s", "quit")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}

	// wait for the NGINX process to terminate
	timer := time.NewTicker(time.Second * 1)
	for range timer.C {
		if !nginx.IsRunning() {
			klog.InfoS("NGINX process has stopped")
			timer.Stop()
			break
		}
	}

	return nil
}

func (n *NGINXController) start(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		klog.Fatalf("NGINX error: %v", err)
		n.ngxErrCh <- err
		return
	}

	go func() {
		n.ngxErrCh <- cmd.Wait()
	}()
}

// DefaultEndpoint returns the default endpoint to be use as default server that returns 404.
func (n NGINXController) DefaultEndpoint() ingress.Endpoint {
	return ingress.Endpoint{
		Address: "127.0.0.1",
		Port:    fmt.Sprintf("%v", n.cfg.ListenPorts.Default),
		Target:  &apiv1.ObjectReference{},
	}
}

// generateTemplate returns the nginx configuration file content
// 通过模板生成 nginx 配置
func (n NGINXController) generateTemplate(cfg ngx_config.Configuration, ingressCfg ingress.Configuration) ([]byte, error) {

	// 处理 ssl 配置
	if n.cfg.EnableSSLPassthrough {
		servers := []*tcpproxy.TCPServer{}
		for _, pb := range ingressCfg.PassthroughBackends {
			svc := pb.Service
			if svc == nil {
				klog.Warningf("Missing Service for SSL Passthrough backend %q", pb.Backend)
				continue
			}
			port, err := strconv.Atoi(pb.Port.String()) // #nosec
			if err != nil {
				for _, sp := range svc.Spec.Ports {
					if sp.Name == pb.Port.String() {
						port = int(sp.Port)
						break
					}
				}
			} else {
				for _, sp := range svc.Spec.Ports {
					if sp.Port == int32(port) {
						port = int(sp.Port)
						break
					}
				}
			}

			// TODO: Allow PassthroughBackends to specify they support proxy-protocol
			servers = append(servers, &tcpproxy.TCPServer{
				Hostname:      pb.Hostname,
				IP:            svc.Spec.ClusterIP,
				Port:          port,
				ProxyProtocol: false,
			})
		}

		n.Proxy.ServerList = servers
	}

	// NGINX cannot resize the hash tables used to store server names. For
	// this reason we check if the current size is correct for the host
	// names defined in the Ingress rules and adjust the value if
	// necessary.
	// https://trac.nginx.org/nginx/ticket/352
	// https://trac.nginx.org/nginx/ticket/631
	var longestName int
	var serverNameBytes int

	for _, srv := range ingressCfg.Servers {
		hostnameLength := len(srv.Hostname)
		if srv.RedirectFromToWWW {
			hostnameLength += 4
		}
		if longestName < hostnameLength {
			longestName = hostnameLength
		}

		for _, alias := range srv.Aliases {
			if longestName < len(alias) {
				longestName = len(alias)
			}
		}

		serverNameBytes += hostnameLength
	}

	// 设置 nginx 的 server_names_hash_bucket_size, 通过预设 hash bucket 的个数, 来加快查询速度, 减少拉链查询的概率.
	nameHashBucketSize := nginxHashBucketSize(longestName)
	if cfg.ServerNameHashBucketSize < nameHashBucketSize {
		klog.V(3).InfoS("Adjusting ServerNameHashBucketSize variable", "value", nameHashBucketSize)
		cfg.ServerNameHashBucketSize = nameHashBucketSize
	}

	// 设置 nginx 的 map_hash_bucket_size, 搭配上面的配置使用, 提高 nginx hashmap 检索速度.
	serverNameHashMaxSize := nextPowerOf2(serverNameBytes)
	if cfg.ServerNameHashMaxSize < serverNameHashMaxSize {
		klog.V(3).InfoS("Adjusting ServerNameHashMaxSize variable", "value", serverNameHashMaxSize)
		cfg.ServerNameHashMaxSize = serverNameHashMaxSize
	}

	// 设置 nginx 的 worker_rlimit_nofile 每个 worker 可以打开的最大文件描述符数量, 这里的 fd 不仅仅指文件, 还是链接文件描述符 (socket fd).
	if cfg.MaxWorkerOpenFiles == 0 {
		// the limit of open files is per worker process
		// and we leave some room to avoid consuming all the FDs available
		maxOpenFiles := rlimitMaxNumFiles() - 1024
		klog.V(3).InfoS("Maximum number of open file descriptors", "value", maxOpenFiles)
		if maxOpenFiles < 1024 {
			// this means the value of RLIMIT_NOFILE is too low.
			// 最小为 1024
			maxOpenFiles = 1024
		}
		klog.V(3).InfoS("Adjusting MaxWorkerOpenFiles variable", "value", maxOpenFiles)
		cfg.MaxWorkerOpenFiles = maxOpenFiles
	}

	// 配置 nginx worker_connections, 每个 worker 的连接数量, worker_connections 通常要小于 worker_rlimit_nofile, 一个是连接的限制, 一个是所有 fd 的限制.
	if cfg.MaxWorkerConnections == 0 {
		maxWorkerConnections := int(float64(cfg.MaxWorkerOpenFiles * 3.0 / 4))
		klog.V(3).InfoS("Adjusting MaxWorkerConnections variable", "value", maxWorkerConnections)
		cfg.MaxWorkerConnections = maxWorkerConnections
	}

	// 配置转发请求时的 proxy header, 这个从 configmap 里获取.
	setHeaders := map[string]string{}
	if cfg.ProxySetHeaders != "" {
		cmap, err := n.store.GetConfigMap(cfg.ProxySetHeaders)
		if err != nil {
			klog.Warningf("Error reading ConfigMap %q from local store: %v", cfg.ProxySetHeaders, err)
		} else {
			setHeaders = cmap.Data
		}
	}

	// 响应时填充的 header, 同样从 configmap 获取.
	addHeaders := map[string]string{}
	if cfg.AddHeaders != "" {
		cmap, err := n.store.GetConfigMap(cfg.AddHeaders)
		if err != nil {
			klog.Warningf("Error reading ConfigMap %q from local store: %v", cfg.AddHeaders, err)
		} else {
			addHeaders = cmap.Data
		}
	}

	sslDHParam := ""
	if cfg.SSLDHParam != "" {
		secretName := cfg.SSLDHParam

		secret, err := n.store.GetSecret(secretName)
		if err != nil {
			klog.Warningf("Error reading Secret %q from local store: %v", secretName, err)
		} else {
			nsSecName := strings.Replace(secretName, "/", "-", -1)
			dh, ok := secret.Data["dhparam.pem"]
			if ok {
				pemFileName, err := ssl.AddOrUpdateDHParam(nsSecName, dh)
				if err != nil {
					klog.Warningf("Error adding or updating dhparam file %v: %v", nsSecName, err)
				} else {
					sslDHParam = pemFileName
				}
			}
		}
	}

	// 设置 ssl 参数
	cfg.SSLDHParam = sslDHParam

	cfg.DefaultSSLCertificate = n.getDefaultSSLCertificate()

	// 配置 access_log 和 error_log 的位置
	if n.cfg.IsChroot {
		if cfg.AccessLogPath == "/var/log/nginx/access.log" {
			cfg.AccessLogPath = fmt.Sprintf("syslog:server=%s", n.cfg.InternalLoggerAddress)
		}
		if cfg.ErrorLogPath == "/var/log/nginx/error.log" {
			cfg.ErrorLogPath = fmt.Sprintf("syslog:server=%s", n.cfg.InternalLoggerAddress)
		}
	}

	tc := ngx_config.TemplateConfig{
		// 配置请求时自定义的 header 填充, 模板中使用 proxy_set_header 指令
		ProxySetHeaders: setHeaders,
		// 定制响应报文的 header, 模板中使用 more_set_headers 指令
		AddHeaders: addHeaders,
		// 连接全队列的大小, 从 /net/core/somaxconn 获取, 读取失败或者过小则设置为 511.
		BacklogSize:         sysctlSomaxconn(),
		Backends:            ingressCfg.Backends,
		PassthroughBackends: ingressCfg.PassthroughBackends,
		// nginx 的 server 段配置
		Servers: ingressCfg.Servers,
		// nginx stream tcp server 的配置
		TCPBackends: ingressCfg.TCPEndpoints,
		// nginx stream udp server 的配置
		UDPBackends: ingressCfg.UDPEndpoints,
		// ngx_config 配置
		Cfg:                      cfg,
		IsIPV6Enabled:            n.isIPV6Enabled && !cfg.DisableIpv6,
		NginxStatusIpv4Whitelist: cfg.NginxStatusIpv4Whitelist,
		NginxStatusIpv6Whitelist: cfg.NginxStatusIpv6Whitelist,
		// redirect 跳转
		RedirectServers:         utilingress.BuildRedirects(ingressCfg.Servers),
		IsSSLPassthroughEnabled: n.cfg.EnableSSLPassthrough,
		// 监听的端口
		ListenPorts: n.cfg.ListenPorts,
		// 开启 metrics 监控, 这个是在 http lua 逻辑里
		EnableMetrics: n.cfg.EnableMetrics,
		// 主要跟 geolite 有关系
		MaxmindEditionFiles: n.cfg.MaxmindEditionFiles,
		// 在每个 http server 里加入一个 location path 为 /healthz 的接口, 处理逻辑是直接 return  200
		HealthzURI:          nginx.HealthPath,
		MonitorMaxBatchSize: n.cfg.MonitorMaxBatchSize,
		// 声明下 nginx pid 位置在 `/tmp/nginx/nginx.pid`
		PID: nginx.PID,
		// 开启 nginx status 接口
		StatusPath:     nginx.StatusPath,
		StatusPort:     nginx.StatusPort,
		StreamPort:     nginx.StreamPort,
		StreamSnippets: append(ingressCfg.StreamSnippets, cfg.StreamSnippet),
	}

	// 在 nginx.conf 文件头部位置的注释里加入配置的 checksum 校验码, 其实就是配置文件的 hash 值.
	tc.Cfg.Checksum = ingressCfg.ConfigurationChecksum

	// n.t 为 nginx.tmpl 的模板解释器, write 通过传递的 ngx 变量来生成 nginx 配置.
	return n.t.Write(tc)
}

// testTemplate checks if the NGINX configuration inside the byte array is valid
// running the command "nginx -t" using a temporal file.
// 测试并校验 nginx 配置
func (n NGINXController) testTemplate(cfg []byte) error {
	if len(cfg) == 0 {
		return fmt.Errorf("invalid NGINX configuration (empty)")
	}
	// 在 /tmp/nginx 临时目录创建前缀为 `nginx-cfg` 后跟随机数的临时文件.
	tmpDir := os.TempDir() + "/nginx"
	tmpfile, err := os.CreateTemp(tmpDir, tempNginxPattern)
	if err != nil {
		return err
	}
	defer tmpfile.Close()
	err = os.WriteFile(tmpfile.Name(), cfg, file.ReadWriteByUser)
	if err != nil {
		return err
	}
	// 通过 nginx -t -c nginx-cfgxxxx 来测试临时配置是否合法.
	out, err := n.command.Test(tmpfile.Name())
	if err != nil {
		// this error is different from the rest because it must be clear why nginx is not working
		oe := fmt.Sprintf(`
-------------------------------------------------------------------------------
Error: %v
%v
-------------------------------------------------------------------------------
`, err, string(out))

		return errors.New(oe)
	}

	os.Remove(tmpfile.Name())
	return nil
}

// OnUpdate is called by the synchronization loop whenever configuration
// changes were detected. The received backend Configuration is merged with the
// configuration ConfigMap before generating the final configuration file.
// Returns nil in case the backend was successfully reloaded.
// 同步 nginx 配置
func (n *NGINXController) OnUpdate(ingressCfg ingress.Configuration) error {
	cfg := n.store.GetBackendConfiguration()
	cfg.Resolver = n.resolver

	// 通过模板生成 nginx 配置, 赋值给 content 对象里.
	content, err := n.generateTemplate(cfg, ingressCfg)
	if err != nil {
		return err
	}

	// 根据不同的 collector 类型从 zipkin, jaeger 等选定模板, 然后创建 `opentracing` 配置, 把 opentracing 配置写到 /etc/nginx/opentracing.json 里.
	err = createOpentracingCfg(cfg)
	if err != nil {
		return err
	}

	// 使用 `nginx -t -c tmpfile` 来检测临时生成的 nginx 配置文件.
	err = createOpentelemetryCfg(cfg)
	if err != nil {
		return err
	}

	err = n.testTemplate(content)
	if err != nil {
		return err
	}

	// 判断日志级别是否允许 2 level, 允许则打印新旧配置差异的部分.
	if klog.V(2).Enabled() {
		src, _ := os.ReadFile(cfgPath)
		// 如果当前配置跟预期配置不同的话, 获取差异部分并打印输出.
		if !bytes.Equal(src, content) {
			// 把配置放到临时文件里
			tmpfile, err := os.CreateTemp("", "new-nginx-cfg")
			if err != nil {
				return err
			}
			defer tmpfile.Close()
			err = os.WriteFile(tmpfile.Name(), content, file.ReadWriteByUser)
			if err != nil {
				return err
			}

			// 使用 diff 命令判断配置文件的差异
			diffOutput, err := exec.Command("diff", "-I", "'# Configuration.*'", "-u", cfgPath, tmpfile.Name()).CombinedOutput()
			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					ws := exitError.Sys().(syscall.WaitStatus)
					if ws.ExitStatus() == 2 {
						klog.Warningf("Failed to executing diff command: %v", err)
					}
				}
			}

			// 打印配置中有差异的部分
			klog.InfoS("NGINX configuration change", "diff", string(diffOutput))

			// we do not defer the deletion of temp files in order
			// to keep them around for inspection in case of error
			// 删除临时文件
			os.Remove(tmpfile.Name())
		}
	}

	// 把 nginx 配置写到 /etc/nginx/nginx.conf 里.
	err = os.WriteFile(cfgPath, content, file.ReadWriteByUser)
	if err != nil {
		return err
	}

	// 使用 nginx -s reload 进行热加载
	o, err := n.command.ExecCommand("-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v\n%v", err, string(o))
	}

	return nil
}

// nginxHashBucketSize computes the correct NGINX hash_bucket_size for a hash
// with the given longest key.
func nginxHashBucketSize(longestString int) int {
	// see https://github.com/kubernetes/ingress-nginxs/issues/623 for an explanation
	wordSize := 8 // Assume 64 bit CPU
	n := longestString + 2
	aligned := (n + wordSize - 1) & ^(wordSize - 1)
	rawSize := wordSize + wordSize + aligned
	return nextPowerOf2(rawSize)
}

// http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
// https://play.golang.org/p/TVSyCcdxUh
func nextPowerOf2(v int) int {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++

	return v
}

func (n *NGINXController) setupSSLProxy() {
	cfg := n.store.GetBackendConfiguration()
	sslPort := n.cfg.ListenPorts.HTTPS
	proxyPort := n.cfg.ListenPorts.SSLProxy

	klog.InfoS("Starting TLS proxy for SSL Passthrough")
	n.Proxy = &tcpproxy.TCPProxy{
		Default: &tcpproxy.TCPServer{
			Hostname:      "localhost",
			IP:            "127.0.0.1",
			Port:          proxyPort,
			ProxyProtocol: true,
		},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%v", sslPort))
	if err != nil {
		klog.Fatalf("%v", err)
	}

	proxyList := &proxyproto.Listener{Listener: listener, ProxyHeaderTimeout: cfg.ProxyProtocolHeaderTimeout}

	// accept TCP connections on the configured HTTPS port
	go func() {
		for {
			var conn net.Conn
			var err error

			if n.store.GetBackendConfiguration().UseProxyProtocol {
				// wrap the listener in order to decode Proxy
				// Protocol before handling the connection
				conn, err = proxyList.Accept()
			} else {
				conn, err = listener.Accept()
			}

			if err != nil {
				klog.Warningf("Error accepting TCP connection: %v", err)
				continue
			}

			klog.V(3).InfoS("Handling TCP connection", "remote", conn.RemoteAddr(), "local", conn.LocalAddr())
			go n.Proxy.Handle(conn)
		}
	}()
}

// Helper function to clear Certificates from the ingress configuration since they should be ignored when
// checking if the new configuration changes can be applied dynamically if dynamic certificates is on
func clearCertificates(config *ingress.Configuration) {
	var clearedServers []*ingress.Server
	for _, server := range config.Servers {
		copyOfServer := *server
		copyOfServer.SSLCert = nil
		clearedServers = append(clearedServers, &copyOfServer)
	}
	config.Servers = clearedServers
}

// Helper function to clear endpoints from the ingress configuration since they should be ignored when
// checking if the new configuration changes can be applied dynamically.
func clearL4serviceEndpoints(config *ingress.Configuration) {
	var clearedTCPL4Services []ingress.L4Service
	var clearedUDPL4Services []ingress.L4Service
	for _, service := range config.TCPEndpoints {
		copyofService := ingress.L4Service{
			Port:      service.Port,
			Backend:   service.Backend,
			Endpoints: []ingress.Endpoint{},
			Service:   nil,
		}
		clearedTCPL4Services = append(clearedTCPL4Services, copyofService)
	}
	for _, service := range config.UDPEndpoints {
		copyofService := ingress.L4Service{
			Port:      service.Port,
			Backend:   service.Backend,
			Endpoints: []ingress.Endpoint{},
			Service:   nil,
		}
		clearedUDPL4Services = append(clearedUDPL4Services, copyofService)
	}
	config.TCPEndpoints = clearedTCPL4Services
	config.UDPEndpoints = clearedUDPL4Services
}

// configureDynamically encodes new Backends in JSON format and POSTs the
// payload to an internal HTTP endpoint handled by Lua.
// 变更信息通知给 nginx
func (n *NGINXController) configureDynamically(pcfg *ingress.Configuration) error {
	backendsChanged := !reflect.DeepEqual(n.runningConfig.Backends, pcfg.Backends)
	// 当 endpoints 地址发生变更时
	if backendsChanged {
		// 动态修改 http 的 backends
		err := configureBackends(pcfg.Backends)
		if err != nil {
			return err
		}
	}

	streamConfigurationChanged := !reflect.DeepEqual(n.runningConfig.TCPEndpoints, pcfg.TCPEndpoints) || !reflect.DeepEqual(n.runningConfig.UDPEndpoints, pcfg.UDPEndpoints)
	// 当 endpoints 地址发生变更时
	if streamConfigurationChanged {
		// 动态修改 tcp 和 udp 的 backends 地址列表
		err := updateStreamConfiguration(pcfg.TCPEndpoints, pcfg.UDPEndpoints)
		if err != nil {
			return err
		}
	}

	serversChanged := !reflect.DeepEqual(n.runningConfig.Servers, pcfg.Servers)
	// 当 servers 地址发生变更时
	if serversChanged {
		// 动态修改证书相关配置
		err := configureCertificates(pcfg.Servers)
		if err != nil {
			return err
		}
	}

	return nil
}

func updateStreamConfiguration(TCPEndpoints []ingress.L4Service, UDPEndpoints []ingress.L4Service) error {
	streams := make([]ingress.Backend, 0)
	for _, ep := range TCPEndpoints {
		var service *apiv1.Service
		if ep.Service != nil {
			service = &apiv1.Service{Spec: ep.Service.Spec}
		}

		key := fmt.Sprintf("tcp-%v-%v-%v", ep.Backend.Namespace, ep.Backend.Name, ep.Backend.Port.String())
		streams = append(streams, ingress.Backend{
			Name:      key,
			Endpoints: ep.Endpoints,
			Port:      intstr.FromInt(ep.Port),
			Service:   service,
		})
	}
	for _, ep := range UDPEndpoints {
		var service *apiv1.Service
		if ep.Service != nil {
			service = &apiv1.Service{Spec: ep.Service.Spec}
		}

		key := fmt.Sprintf("udp-%v-%v-%v", ep.Backend.Namespace, ep.Backend.Name, ep.Backend.Port.String())
		streams = append(streams, ingress.Backend{
			Name:      key,
			Endpoints: ep.Endpoints,
			Port:      intstr.FromInt(ep.Port),
			Service:   service,
		})
	}

	buf, err := json.Marshal(streams)
	if err != nil {
		return err
	}

	hostPort := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%v", nginx.StreamPort))
	conn, err := net.Dial("tcp", hostPort)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(buf)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(conn, "\r\n")
	if err != nil {
		return err
	}

	return nil
}

func configureBackends(rawBackends []*ingress.Backend) error {
	backends := make([]*ingress.Backend, len(rawBackends))

	for i, backend := range rawBackends {
		var service *apiv1.Service
		if backend.Service != nil {
			service = &apiv1.Service{Spec: backend.Service.Spec}
		}
		luaBackend := &ingress.Backend{
			Name:                 backend.Name,
			Port:                 backend.Port,
			SSLPassthrough:       backend.SSLPassthrough,
			SessionAffinity:      backend.SessionAffinity,
			UpstreamHashBy:       backend.UpstreamHashBy,
			LoadBalancing:        backend.LoadBalancing,
			Service:              service,
			NoServer:             backend.NoServer,
			TrafficShapingPolicy: backend.TrafficShapingPolicy,
			AlternativeBackends:  backend.AlternativeBackends,
		}

		var endpoints []ingress.Endpoint
		for _, endpoint := range backend.Endpoints {
			endpoints = append(endpoints, ingress.Endpoint{
				Address: endpoint.Address,
				Port:    endpoint.Port,
			})
		}

		luaBackend.Endpoints = endpoints
		backends[i] = luaBackend
	}

	statusCode, _, err := nginx.NewPostStatusRequest("/configuration/backends", "application/json", backends)
	if err != nil {
		return err
	}

	if statusCode != http.StatusCreated {
		return fmt.Errorf("unexpected error code: %d", statusCode)
	}

	return nil
}

type sslConfiguration struct {
	Certificates map[string]string `json:"certificates"`
	Servers      map[string]string `json:"servers"`
}

// configureCertificates JSON encodes certificates and POSTs it to an internal HTTP endpoint
// that is handled by Lua
// 动态修改证书相关配置
func configureCertificates(rawServers []*ingress.Server) error {
	configuration := &sslConfiguration{
		Certificates: map[string]string{},
		Servers:      map[string]string{},
	}

	configure := func(hostname string, sslCert *ingress.SSLCert) {
		uid := emptyUID

		if sslCert != nil {
			uid = sslCert.UID

			if _, ok := configuration.Certificates[uid]; !ok {
				configuration.Certificates[uid] = sslCert.PemCertKey
			}
		}

		configuration.Servers[hostname] = uid
	}

	for _, rawServer := range rawServers {
		configure(rawServer.Hostname, rawServer.SSLCert)

		for _, alias := range rawServer.Aliases {
			if rawServer.SSLCert != nil && ssl.IsValidHostname(alias, rawServer.SSLCert.CN) {
				configuration.Servers[alias] = rawServer.SSLCert.UID
			} else {
				configuration.Servers[alias] = emptyUID
			}
		}
	}

	redirects := utilingress.BuildRedirects(rawServers)
	for _, redirect := range redirects {
		configure(redirect.From, redirect.SSLCert)
	}

	statusCode, _, err := nginx.NewPostStatusRequest("/configuration/servers", "application/json", configuration)
	if err != nil {
		return err
	}

	if statusCode != http.StatusCreated {
		return fmt.Errorf("unexpected error code: %d", statusCode)
	}

	return nil
}

const zipkinTmpl = `{
  "service_name": "{{ .ZipkinServiceName }}",
  "collector_host": "{{ .ZipkinCollectorHost }}",
  "collector_port": {{ .ZipkinCollectorPort }},
  "sample_rate": {{ .ZipkinSampleRate }}
}`

const jaegerTmpl = `{
  "service_name": "{{ .JaegerServiceName }}",
  "propagation_format": "{{ .JaegerPropagationFormat }}",
  "sampler": {
	"type": "{{ .JaegerSamplerType }}",
	"param": {{ .JaegerSamplerParam }},
	"samplingServerURL": "{{ .JaegerSamplerHost }}:{{ .JaegerSamplerPort }}/sampling"
  },
  "reporter": {
	"endpoint": "{{ .JaegerEndpoint }}",
	"localAgentHostPort": "{{ .JaegerCollectorHost }}:{{ .JaegerCollectorPort }}"
  },
  "headers": {
	"TraceContextHeaderName": "{{ .JaegerTraceContextHeaderName }}",
	"jaegerDebugHeader": "{{ .JaegerDebugHeader }}",
	"jaegerBaggageHeader": "{{ .JaegerBaggageHeader }}",
	"traceBaggageHeaderPrefix": "{{ .JaegerTraceBaggageHeaderPrefix }}"
  }
}`

const datadogTmpl = `{
  "service": "{{ .DatadogServiceName }}",
  "agent_host": "{{ .DatadogCollectorHost }}",
  "agent_port": {{ .DatadogCollectorPort }},
  "environment": "{{ .DatadogEnvironment }}",
  "operation_name_override": "{{ .DatadogOperationNameOverride }}",
  "sample_rate": {{ .DatadogSampleRate }},
  "dd.priority.sampling": {{ .DatadogPrioritySampling }}
}`

const otelTmpl = `
exporter = "otlp"
processor = "batch"

[exporters.otlp]
# Alternatively the OTEL_EXPORTER_OTLP_ENDPOINT environment variable can also be used.
host = "{{ .OtlpCollectorHost }}"
port = {{ .OtlpCollectorPort }}

[processors.batch]
max_queue_size = {{ .OtelMaxQueueSize }}
schedule_delay_millis = {{ .OtelScheduleDelayMillis }}
max_export_batch_size = {{ .OtelMaxExportBatchSize }}

[service]
name = "{{ .OtelServiceName }}" # Opentelemetry resource name

[sampler]
name = "{{ .OtelSampler }}" # Also: AlwaysOff, TraceIdRatioBased
ratio = {{ .OtelSamplerRatio }}
parent_based = {{ .OtelSamplerParentBased }}
`

func createOpentracingCfg(cfg ngx_config.Configuration) error {
	var tmpl *template.Template
	var err error

	if cfg.ZipkinCollectorHost != "" {
		tmpl, err = template.New("zipkin").Parse(zipkinTmpl)
		if err != nil {
			return err
		}
	} else if cfg.JaegerCollectorHost != "" || cfg.JaegerEndpoint != "" {
		tmpl, err = template.New("jaeger").Parse(jaegerTmpl)
		if err != nil {
			return err
		}
	} else if cfg.DatadogCollectorHost != "" {
		tmpl, err = template.New("datadog").Parse(datadogTmpl)
		if err != nil {
			return err
		}
	} else {
		tmpl, _ = template.New("empty").Parse("{}")
	}

	tmplBuf := bytes.NewBuffer(make([]byte, 0))
	err = tmpl.Execute(tmplBuf, cfg)
	if err != nil {
		return err
	}

	// Expand possible environment variables before writing the configuration to file.
	expanded := os.ExpandEnv(tmplBuf.String())

	return os.WriteFile("/etc/nginx/opentracing.json", []byte(expanded), file.ReadWriteByUser)
}

func createOpentelemetryCfg(cfg ngx_config.Configuration) error {

	tmpl, err := template.New("otel").Parse(otelTmpl)
	if err != nil {
		return err
	}
	tmplBuf := bytes.NewBuffer(make([]byte, 0))
	err = tmpl.Execute(tmplBuf, cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(cfg.OpentelemetryConfig, tmplBuf.Bytes(), file.ReadWriteByUser)
}

func cleanTempNginxCfg() error {
	var files []string

	err := filepath.Walk(os.TempDir(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && os.TempDir() != path {
			return filepath.SkipDir
		}

		dur, _ := time.ParseDuration("-5m")
		fiveMinutesAgo := time.Now().Add(dur)
		if strings.HasPrefix(info.Name(), tempNginxPattern) && info.ModTime().Before(fiveMinutesAgo) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			return err
		}
	}

	return nil
}
