package main

import (
	"bufio"
	_ "embed"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"text/template"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ConfigDir                   string `yaml:"config_dir"`
	URTimezone                  string `yaml:"ur_timezone"`
	UnboundDNSEnable            bool   `yaml:"unbound_dns_enable"`
	UnboundDBSIdentity          string `yaml:"unbound_dns_identitiy"`
	UndoundDNSHide              bool   `yaml:"unbound_dns_hide"`
	UnboundDNSIpV4              bool   `yaml:"unbound_dns_ipv4"`
	UnboundDNSIpV6              bool   `yaml:"unbound_dns_ipv6"`
	UnboundDNSNumThreads        string `yaml:"unbound_dns_num_threads"`
	UnboundDNSUpstream          string `yaml:"unbound_dns_upstream_4_pihole"`
	PiholeEnable                bool   `yaml:"pihole_enable"`
	PiholeWithUnbound           bool   `yaml:"pihole_with_unbound"`
	PiholePassword              string `yaml:"pihole_password"`
	PiholeHostname              string `yaml:"pihole_hostname"`
	TechDNSEnable               bool   `yaml:"tech_dns_enable"`
	TechDNSPassword             string `yaml:"tech_dns_password"`
	TechDNSHostname             string `yaml:"tech_dns_hostname"`
	TechDNSIpv6                 bool   `yaml:"tech_dns_ipv6"`
	TechDNSBlocking             bool   `yaml:"tech_dns_blocking"`
	TechDNSForwaders            string `yaml:"tech_dns_forwarders"`
	TechDNSForwaderProtocol     string `yaml:"tech_dns_forwarder_proto"`
	TechDNSServer               string `yaml:"tech_dns_server"`
	OpenVPNServer               bool   `yaml:"ovpn_server_enable"`
	OpenVPNUIUser               string `yaml:"ovpnui_user"`
	OpenVPNUIPassword           string `yaml:"ovpnui_password"`
	OpenVPNServerTrusSub        string `yaml:"ovpn_trusted_subnet"`
	OpenVPNServerGuestSub       string `yaml:"ovpn_guest_subnet"`
	OpenVPNServerHomeSub        string `yaml:"ovpn_home_subnet"`
	OpenVPNServerRemoteOpt      string `yaml:"ovpn_remote"`
	OpenVPNClient               bool   `yaml:"ovpn_client_enable"`
	OpenVPNClientCert           string `yaml:"ovpn_client_cert"`
	OpenVPNClientAllowedSub     string `yaml:"ovpn_client_allowed_subnet"`
	OpenVPNClientSecret         string `yaml:"ovpn_client_secret"`
	OpenVPNClientKillSwitch     bool   `yaml:"ovpn_client_killswitch"`
	WireGuardServer             bool   `yaml:"wireguard_server_enable"`
	WireGuardUIUser             string `yaml:"wireguard_user"`
	WireGuardServerPassword     string `yaml:"wireguard_password"`
	WireGuardServerUrl          string `yaml:"wireguard_serverurl"`
	PortainerEnable             bool   `yaml:"portainer_enable"`
	QbitTorrentEnable           bool   `yaml:"qbittorrent_enable"`
	QbitTorrentPassword         string `yaml:"qbittorrent_default_password"`
	QbitTorrentInVPN            bool   `yaml:"qbittorrent_inside_vpn"`
	QbitTorrentInGluetun        bool   `yaml:"qbittorrent_inside_gluetun"`
	QbitTorrentWebuiPort        string `yaml:"qbittorrent_webui_port"`
	MonitoringEnable            bool   `yaml:"monitoring_enable"`
	MonitoringGrafPassword      string `yaml:"monitoring_grafana_admin_password"`
	MonitoringDays2Keep         string `yaml:"monitoring_days_keep_interval"`
	MonitoringSpeedTestInterval string `yaml:"monitoring_speedtest_interval"`
	MonitoringPingInterval      string `yaml:"monitoring_ping_interval"`
	OpenVPNMonitoringEnable     bool   `yaml:"openvpn_monitoring_enable"`
	PiKVMMonitoringEnable       bool   `yaml:"pikvm_monitoring_enable"`
	PiKVMtargetIp               string `yaml:"pikvm_target_ip"`
	PiKVMwebUser                string `yaml:"pikvm_web_user"`
	PiKVMwebPassword            string `yaml:"pikvm_web_password"`
	AirGradientMonitoring       bool   `yaml:"airgradient_monitoring_enable"`
	StarLinkMonitoring          bool   `yaml:"starlink_monitoring_enable"`
	StarLinkIP                  string `yaml:"starlink_ip"`
	StarLinkPort                string `yaml:"starlink_port"`
	ShellyPlugMonitoring        bool   `yaml:"shelly_plug_monitoring_enable"`
	ShellyPlugHostname          string `yaml:"shelly_plug_hostname"`
	ShellyPlugIP                string `yaml:"shelly_ip"`
	ShellyPlugPort              string `yaml:"shelly_port"`
	ShellyPlugHttpUser          string `yaml:"shelly_plug_http_username"`
	ShellyPlugHttpPassword      string `yaml:"shelly_plug_http_password"`
	GluetunEnable               bool   `yaml:"gluetun_vpnclient_enable"`
	GluetunServerCountries      string `yaml:"gluetun_server_countries"`
	GluetunServerCities         string `yaml:"gluetun_server_cities"`
	GluetunServerUpdatePer      string `yaml:"gluetun_server_update_per"`
	GluetunServiceProvider      string `yaml:"gluetun_vpn_service_provider"`
	GluetunVPNType              string `yaml:"gluetun_vpn_type"`
	GluetunOpenvpnUser          string `yaml:"gluetun_openvpn_user"`
	GluetunOpenvpnPassword      string `yaml:"gluetun_openvpn_password"`
	GluetunVPNCluentCustom      bool   `yaml:"gluetun_vpnclient_custom"`
	GluetunOVPNCusomConfig      string `yaml:"glue_ovpn_custom_conf"`
	GluetunWGPrivateKey         string `yaml:"gluetun_wireguard_private_key"`
	GluetunWGPublicKey          string `yaml:"gluetun_wireguard_public_key"`
	GluetunWGPresharedKey       string `yaml:"gluetun_wireguard_preshared_key"`
	GluetunWGAddress            string `yaml:"gluetun_wireguard_address"`
	GluetunWGEndpointIP         string `yaml:"gluetun_wireguard_endpoint_ip"`
	GluetunWGEndpointPort       string `yaml:"gluetun_wireguard_endpoint_port"`
	IPAddress                   string // to pass your IP address to the template
}

type InventoryConfig struct {
	All struct {
		Hosts struct {
			RaspberryGateway struct {
				IP                string `yaml:"ansible_host"`
				AnsibleUser       string `yaml:"ansible_user"`
				AnsibleConnection string `yaml:"ansible_connection"`
				AnsibleUse        string `yaml:"ansible_use"`
			} `yaml:"raspberry_gateway"`
		} `yaml:"hosts"`
	} `yaml:"all"`
}

//go:embed config.html
var configHTML string

func main() {
	// Copy example.config.yml to config.yml
	err := copyFile("example.config.yml", "config.yml")
	copyFile("example.inventory.yml", "inventory.yml")
	if err != nil {
		log.Fatal(err)
	}
	//log.Printf("DBG: example.config.yml copied to config.yml")
	//log.Printf("DBG: example.inventory.yml copied to inventory.yml")

	// Truncate the webinstall.log file
	f, err := os.OpenFile("webinstall.log", os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	//log.Printf("DBG: webinstall.log truncated")

	// Write "announcement" to the webinstall.log file
	if _, err := f.WriteString("Here will be the log of Raspberry Gateway installation progress, after you'll press \"Install\" button.\n"); err != nil {
		log.Fatal(err)
	}
	//log.Printf("DBG: webinstall.log updated with \"announcement\"")

	// Log the welcome message
	log.Printf("Welcome! The web interface will guide you on installation process.\nInstallation logs: webinstall.log\n")

	// Create a new router
	r := http.NewServeMux()

	// Register the routes
	r.HandleFunc("/", editConfig)
	r.HandleFunc("/save", saveConfig)
	r.HandleFunc("/install", install)
	r.HandleFunc("/webinstall.log", func(w http.ResponseWriter, r *http.Request) {

		// Open the webinstall.log file
		f, err := os.Open("webinstall.log")
		if err != nil {
			http.Error(w, "Error opening file", http.StatusInternalServerError)
			return
		}
		defer f.Close()

		// Create a new reader that reads from the file
		reader := bufio.NewReader(f)

		// Continuously read new lines from the file and write them to the response
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				http.Error(w, "Error reading file", http.StatusInternalServerError)
				return
			}
			_, err = w.Write([]byte(line))
			if err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})

	// Handle file uploads
	r.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		//log.Printf("DBG: /upload called from webui")

		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Get the type of configuration file to upload from the query parameter
		fileType := r.URL.Query().Get("type")
		if fileType == "" {
			http.Error(w, "File type not specified", http.StatusBadRequest)
			return
		}

		// Create a new file to write the uploaded file contents to
		var filePath string
		switch fileType {
		case "openvpn":
			filePath = "openvpn-client/webinstall-client.ovpn"
		case "openvpn-secret":
			filePath = "openvpn-client/webinstall-credentials.txt"
		case "gluetun":
			filePath = "gluetun/ovpn-client/webinstall-client.ovpn"
		default:
			http.Error(w, "Invalid file type specified", http.StatusBadRequest)
			return
		}
		f, err := os.Create(filePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		//log.Printf("DBG: File created: %s", f.Name())

		// Copy the contents of the uploaded file to the new file
		_, err = io.Copy(f, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		//log.Printf("DBG: %s file upload successfully", fileType)
	})

	// Create a new server
	srv := &http.Server{
		Addr:    ":8088",
		Handler: r,
	}

	ip, err := getServerIP()
	if err != nil {
		log.Fatalf("Failed to get server IP: %v", err)
	}

	// Log the server startup message
	log.Printf("Starting web server on http://%s%s\n", ip, srv.Addr)
	// Start the server
	err = srv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
	// Log the server shutdown message
	log.Println("Server stopped.")
}

func getServerIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", nil
}

func readInventoryConfig() (InventoryConfig, error) {
	var config InventoryConfig
	file, err := os.Open("inventory.yml")
	if err != nil {
		return config, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return config, err
	}
	data := make([]byte, stat.Size())
	_, err = file.Read(data)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}
	//log.Printf("DBG: Func Read inventory config. Data:\n")
	//log.Printf("DBG: %+v", config)
	return config, nil
}

func writeInventoryConfig(config InventoryConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	file, err := os.Create("inventory.yml")
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return err
	}
	//log.Printf("DBG: Func Write inventory config")
	return nil
}

func editConfig(w http.ResponseWriter, r *http.Request) {
	config, err := readConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//log.Printf("DBG: editConfig called. Starting to read inventory config")

	inventoryConfig, err := readInventoryConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//log.Printf("DBG: inventory config read. Starting to get server IP")

	ip, err := getServerIP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	config.IPAddress = ip // Add the IP address to the config variable

	tmpl, err := template.New("config").Parse(configHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type TemplateData struct {
		Config          Config
		InventoryConfig InventoryConfig
	}
	//log.Printf("DBG: defined TemplateData struct. for inventory")

	data := TemplateData{
		Config:          config,
		InventoryConfig: inventoryConfig,
	}
	//log.Printf("DBG: defined data constan. Starting to combine template with data:\n")
	//log.Printf("DBG: %+v", data)

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func saveConfig(w http.ResponseWriter, r *http.Request) {
	config := Config{
		ConfigDir:                   r.FormValue("config_dir"),
		URTimezone:                  r.FormValue("ur_timezone"),
		UnboundDNSEnable:            r.FormValue("unbound_dns_enable") == "on",
		UnboundDBSIdentity:          r.FormValue("unbound_dns_identitiy"),
		UndoundDNSHide:              r.FormValue("unbound_dns_hide") == "on",
		UnboundDNSIpV4:              r.FormValue("unbound_dns_ipv4") == "on",
		UnboundDNSIpV6:              r.FormValue("unbound_dns_ipv6") == "on",
		UnboundDNSNumThreads:        r.FormValue("unbound_dns_num_threads"),
		UnboundDNSUpstream:          r.FormValue("unbound_dns_upstream_4_pihole"),
		PiholeEnable:                r.FormValue("pihole_enable") == "on",
		PiholeWithUnbound:           r.FormValue("pihole_with_unbound") == "on",
		PiholePassword:              r.FormValue("pihole_password"),
		PiholeHostname:              "pihole",
		TechDNSEnable:               r.FormValue("tech_dns_enable") == "on",
		TechDNSPassword:             r.FormValue("tech_dns_password"),
		TechDNSHostname:             r.FormValue("tech_dns_hostname"),
		TechDNSServer:               r.FormValue("tech_dns_server"),
		TechDNSIpv6:                 r.FormValue("tech_dns_ipv6") == "on",
		TechDNSBlocking:             r.FormValue("tech_dns_blocking") == "on",
		TechDNSForwaders:            r.FormValue("tech_dns_forwarders"),
		TechDNSForwaderProtocol:     r.FormValue("tech_dns_forwarder_proto"),
		OpenVPNServer:               r.FormValue("ovpn_server_enable") == "on",
		OpenVPNUIUser:               r.FormValue("ovpnui_user"),
		OpenVPNUIPassword:           r.FormValue("ovpnui_password"),
		OpenVPNServerTrusSub:        r.FormValue("ovpn_trusted_subnet"),
		OpenVPNServerGuestSub:       r.FormValue("ovpn_guest_subnet"),
		OpenVPNServerHomeSub:        r.FormValue("ovpn_home_subnet"),
		OpenVPNServerRemoteOpt:      r.FormValue("ovpn_remote"),
		OpenVPNClient:               r.FormValue("ovpn_client_enable") == "on",
		OpenVPNClientCert:           "webinstall-client.ovpn",
		OpenVPNClientAllowedSub:     r.FormValue("ovpn_client_allowed_subnet"),
		OpenVPNClientSecret:         "webinstall-credentials.txt",
		OpenVPNClientKillSwitch:     r.FormValue("ovpn_client_killswitch") == "on",
		WireGuardServer:             r.FormValue("wireguard_server_enable") == "on",
		WireGuardUIUser:             r.FormValue("wireguard_user"),
		WireGuardServerPassword:     r.FormValue("wireguard_password"),
		WireGuardServerUrl:          r.FormValue("wireguard_serverurl"),
		PortainerEnable:             r.FormValue("portainer_enable") == "on",
		QbitTorrentEnable:           r.FormValue("qbittorrent_enable") == "on",
		QbitTorrentPassword:         "adminadmin",
		QbitTorrentInVPN:            r.FormValue("qbittorrent_inside_vpn") == "on",
		QbitTorrentInGluetun:        r.FormValue("qbittorrent_inside_gluetun") == "on",
		QbitTorrentWebuiPort:        r.FormValue("qbittorrent_webui_port"),
		MonitoringEnable:            r.FormValue("monitoring_enable") == "on",
		MonitoringGrafPassword:      r.FormValue("monitoring_grafana_admin_password"),
		MonitoringDays2Keep:         r.FormValue("monitoring_days_keep_interval"),
		MonitoringSpeedTestInterval: r.FormValue("monitoring_speedtest_interval"),
		MonitoringPingInterval:      r.FormValue("monitoring_ping_interval"),
		OpenVPNMonitoringEnable:     r.FormValue("openvpn_monitoring_enable") == "on",
		PiKVMMonitoringEnable:       r.FormValue("pikvm_monitoring_enable") == "on",
		PiKVMtargetIp:               r.FormValue("pikvm_target_ip"),
		PiKVMwebUser:                r.FormValue("pikvm_web_user"),
		PiKVMwebPassword:            r.FormValue("pikvm_web_password"),
		AirGradientMonitoring:       r.FormValue("airgradient_monitoring_enable") == "on",
		StarLinkMonitoring:          r.FormValue("starlink_monitoring_enable") == "on",
		StarLinkIP:                  r.FormValue("starlink_ip"),
		StarLinkPort:                r.FormValue("starlink_port"),
		ShellyPlugMonitoring:        r.FormValue("shelly_plug_monitoring_enable") == "on",
		ShellyPlugHostname:          r.FormValue("shelly_plug_hostname"),
		ShellyPlugIP:                r.FormValue("shelly_ip"),
		ShellyPlugPort:              r.FormValue("shelly_port"),
		ShellyPlugHttpUser:          r.FormValue("shelly_plug_http_username"),
		ShellyPlugHttpPassword:      r.FormValue("shelly_plug_http_password"),
		GluetunEnable:               r.FormValue("gluetun_vpnclient_enable") == "on",
		GluetunServerCountries:      r.FormValue("gluetun_server_countries"),
		GluetunServerCities:         r.FormValue("gluetun_server_cities"),
		GluetunServerUpdatePer:      r.FormValue("gluetun_server_update_per"),
		GluetunServiceProvider:      r.FormValue("gluetun_vpn_service_provider"),
		GluetunVPNType:              r.FormValue("gluetun_vpn_type"),
		GluetunOpenvpnUser:          r.FormValue("gluetun_openvpn_user"),
		GluetunOpenvpnPassword:      r.FormValue("gluetun_openvpn_password"),
		GluetunVPNCluentCustom:      r.FormValue("gluetun_vpnclient_custom") == "on",
		GluetunOVPNCusomConfig:      "webinstall-client.ovpn",
		GluetunWGPrivateKey:         r.FormValue("gluetun_wireguard_private_key"),
		GluetunWGPublicKey:          r.FormValue("gluetun_wireguard_public_key"),
		GluetunWGPresharedKey:       r.FormValue("gluetun_wireguard_preshared_key"),
		GluetunWGAddress:            r.FormValue("gluetun_wireguard_address"),
		GluetunWGEndpointIP:         r.FormValue("gluetun_wireguard_endpoint_ip"),
		GluetunWGEndpointPort:       r.FormValue("gluetun_wireguard_endpoint_port"),
	}
	err := writeConfig(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//log.Printf("DBG: main config saved")

	inventoryConfig := InventoryConfig{
		All: struct {
			Hosts struct {
				RaspberryGateway struct {
					IP                string `yaml:"ansible_host"`
					AnsibleUser       string `yaml:"ansible_user"`
					AnsibleConnection string `yaml:"ansible_connection"`
					AnsibleUse        string `yaml:"ansible_use"`
				} `yaml:"raspberry_gateway"`
			} `yaml:"hosts"`
		}{
			Hosts: struct {
				RaspberryGateway struct {
					IP                string `yaml:"ansible_host"`
					AnsibleUser       string `yaml:"ansible_user"`
					AnsibleConnection string `yaml:"ansible_connection"`
					AnsibleUse        string `yaml:"ansible_use"`
				} `yaml:"raspberry_gateway"`
			}{
				RaspberryGateway: struct {
					IP                string `yaml:"ansible_host"`
					AnsibleUser       string `yaml:"ansible_user"`
					AnsibleConnection string `yaml:"ansible_connection"`
					AnsibleUse        string `yaml:"ansible_use"`
				}{
					IP:                r.FormValue("raspberry_gateway_ip"),
					AnsibleUser:       r.FormValue("raspberry_gateway_ansible_user"),
					AnsibleConnection: r.FormValue("raspberry_gateway_ansible_connection"),
					AnsibleUse:        r.FormValue("raspberry_gateway_ansible_use"),
				},
			},
		},
	}
	//log.Printf("DBG: Inventory config saved. Starting writeInventoryConfig")

	err = writeInventoryConfig(inventoryConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//log.Printf("DBG: writeInventoryConfig done. redirecting to /")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func readConfig() (Config, error) {
	var config Config
	file, err := os.Open("config.yml")
	if err != nil {
		return config, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return config, err
	}
	data := make([]byte, stat.Size())
	_, err = file.Read(data)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}
	return config, nil
}

func writeConfig(config Config) error {
	if config.ConfigDir == "" {
		config.ConfigDir = "~"
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	file, err := os.Create("config.yml")
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, input, 0644)
	if err != nil {
		return err
	}
	return nil
}

func install(w http.ResponseWriter, r *http.Request) {
	go func() {
		cmd := exec.Command("ansible-playbook", "main.yml", "-i", "inventory.yml")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}
		defer stdout.Close()

		file, err := os.Create("webinstall.log")
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		writer := io.MultiWriter(os.Stdout, file)
		cmd.Stdout = writer
		cmd.Stderr = os.Stderr

		err = cmd.Start()
		if err != nil {
			log.Fatal(err)
		}

		err = cmd.Wait()
		if err != nil {
			log.Fatal(err)
		}

		// Open the file in append mode and write the new line to it
		f, err := os.OpenFile("webinstall.log", os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		// Write "install complete" to the webinstall.log file
		if _, err := f.WriteString("Installation completed! \nIf there is zero failed tasks - \"failed=0\", you good! \n"); err != nil {
			log.Fatal(err)
			log.Println("Installation completed!")
		}

	}()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
