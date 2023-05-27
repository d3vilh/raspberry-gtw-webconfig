package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"text/template"

	_ "embed"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ConfigDir               string `yaml:"config_dir"`
	URTimezone              string `yaml:"ur_timezone"`
	UnboundDNSEnable        bool   `yaml:"unbound_dns_enable"`
	PiholeEnable            bool   `yaml:"pihole_enable"`
	PiholeWithUnbound       bool   `yaml:"pihole_with_unbound"`
	PiholePassword          string `yaml:"pihole_password"`
	TechDNSEnable           bool   `yaml:"tech_dns_enable"`
	TechDNSPassword         string `yaml:"tech_dns_password"`
	OpenVPNServer           bool   `yaml:"ovpn_server_enable"`
	OpenVPNUIPassword       string `yaml:"ovpnui_password"`
	OpenVPNClient           bool   `yaml:"ovpn_client_enable"`
	OpenVPNClientCert       string `yaml:"ovpn_client_cert"`
	OpenVPNClientAllowedSub string `yaml:"ovpn_client_allowed_subnet"`
	WireGuardServer         bool   `yaml:"wireguard_server_enable"`
	WireGuardServerPassword string `yaml:"wireguard_password"`
	PortainerEnable         bool   `yaml:"portainer_enable"`
	QbitTorrentEnable       bool   `yaml:"qbittorrent_enable"`
	QbitTorrentPassword     string `yaml:"qbittorrent_default_password"`
	QbitTorrentInVPN        bool   `yaml:"qbittorrent_inside_vpn"`
	MonitoringEnable        bool   `yaml:"monitoring_enable"`
	MonitoringGrafPassword  string `yaml:"monitoring_grafana_admin_password"`
	OpenVPNMonitoringEnable bool   `yaml:"openvpn_monitoring_enable"`
	PiKVMMonitoringEnable   bool   `yaml:"pikvm_monitoring_enable"`
	AirGradientMonitoring   bool   `yaml:"airgradient_monitoring_enable"`
	StarLinkMonitoring      bool   `yaml:"starlink_monitoring_enable"`
	ShellyPlugMonitoring    bool   `yaml:"shelly_plug_monitoring_enable"`
}

//go:embed config.html
var configHTML string

func main() {
	// Copy example.config.yml to config.yml
	err := copyFile("example.config.yml", "config.yml")
	if err != nil {
		log.Fatal(err)
	}

	// Log the welcome message
	log.Printf("Welcome! The web interface will guide you on installation process.\n")

	// Create a new router
	r := mux.NewRouter()

	// Register the routes
	r.HandleFunc("/", editConfig)
	r.HandleFunc("/save", saveConfig)
	r.HandleFunc("/install", install)

	// Create a new server
	srv := &http.Server{
		Addr:    ":8088",
		Handler: r,
	}

	// Log the server startup message
	log.Printf("Starting web server on %s...\n", srv.Addr)

	// Start the server
	err = srv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}

	// Log the server shutdown message
	log.Println("Server stopped.")
}

func editConfig(w http.ResponseWriter, r *http.Request) {
	config, err := readConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("config").Parse(configHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func saveConfig(w http.ResponseWriter, r *http.Request) {
	config := Config{
		ConfigDir:               r.FormValue("config_dir"),
		URTimezone:              r.FormValue("ur_timezone"),
		UnboundDNSEnable:        r.FormValue("unbound_dns_enable") == "on",
		PiholeEnable:            r.FormValue("pihole_enable") == "on",
		PiholeWithUnbound:       r.FormValue("pihole_with_unbound") == "on",
		PiholePassword:          r.FormValue("pihole_password"),
		TechDNSEnable:           r.FormValue("tech_dns_enable") == "on",
		TechDNSPassword:         r.FormValue("tech_dns_password"),
		OpenVPNServer:           r.FormValue("ovpn_server_enable") == "on",
		OpenVPNUIPassword:       r.FormValue("ovpnui_password"),
		OpenVPNClient:           r.FormValue("ovpn_client_enable") == "on",
		OpenVPNClientCert:       r.FormValue("ovpn_client_cert"),
		OpenVPNClientAllowedSub: r.FormValue("ovpn_client_allowed_subnet"),
		WireGuardServer:         r.FormValue("wireguard_server_enable") == "on",
		WireGuardServerPassword: r.FormValue("wireguard_password"),
		PortainerEnable:         r.FormValue("portainer_enable") == "on",
		QbitTorrentEnable:       r.FormValue("qbittorrent_enable") == "on",
		QbitTorrentPassword:     r.FormValue("qbittorrent_default_password"),
		QbitTorrentInVPN:        r.FormValue("qbittorrent_inside_vpn") == "on",
		MonitoringEnable:        r.FormValue("monitoring_enable") == "on",
		MonitoringGrafPassword:  r.FormValue("monitoring_grafana_admin_password"),
		OpenVPNMonitoringEnable: r.FormValue("openvpn_monitoring_enable") == "on",
		PiKVMMonitoringEnable:   r.FormValue("pikvm_monitoring_enable") == "on",
		AirGradientMonitoring:   r.FormValue("airgradient_monitoring_enable") == "on",
		StarLinkMonitoring:      r.FormValue("starlink_monitoring_enable") == "on",
		ShellyPlugMonitoring:    r.FormValue("shelly_plug_monitoring_enable") == "on",
	}

	err := writeConfig(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func install(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("ansible-playbook", "main.yml")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Installation complete!")
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
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dst, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
