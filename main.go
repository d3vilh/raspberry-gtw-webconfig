package main

import (
	"bufio"
	_ "embed"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"text/template"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ConfigDir         string `yaml:"config_dir"`
	UnboundDNSEnable  bool   `yaml:"unbound_dns_enable"`
	PiholeEnable      bool   `yaml:"pihole_enable"`
	PiholeWithUnbound bool   `yaml:"pihole_with_unbound"`
	PiholePassword    string `yaml:"pihole_password"`
	TechDNSEnable     bool   `yaml:"tech_dns_enable"`
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
	r.HandleFunc("/output.txt", func(w http.ResponseWriter, r *http.Request) {
		// Truncate the output.txt file
		//	err := os.Truncate("output.txt", 0)
		//	if err != nil {
		//		http.Error(w, "Error truncating file", http.StatusInternalServerError)
		//		return
		//	}
		// Open the output.txt file
		f, err := os.Open("output.txt")
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
		ConfigDir:         r.FormValue("config_dir"),
		UnboundDNSEnable:  r.FormValue("unbound_dns_enable") == "on",
		PiholeEnable:      r.FormValue("pihole_enable") == "on",
		PiholeWithUnbound: r.FormValue("pihole_with_unbound") == "on",
		PiholePassword:    r.FormValue("pihole_password"),
		TechDNSEnable:     r.FormValue("tech_dns_enable") == "on",
	}
	err := writeConfig(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func install(w http.ResponseWriter, r *http.Request) {
	go func() {
		cmd := exec.Command("ansible-playbook", "main.yml")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}
		defer stdout.Close()

		file, err := os.Create("output.txt")
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

		// Extract the last 20 lines of the output and redirect them to the file
		cmd = exec.Command("tail", "-n", "20", "output.txt")
		output, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
		}

		err = ioutil.WriteFile("output.txt", output, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}()
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
