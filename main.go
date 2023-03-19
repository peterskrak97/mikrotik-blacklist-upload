package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// TALOS URL
var talosURL string = "https://www.talosintelligence.com/documents/ip-blacklist"

// MIKROTIK FORMAT FOR ADDRESS-LIST
type BlackList struct {
	IP       string `json:"address"`
	Disabled string `json:"disabled"`
	Dynamic  string `json:"dynamic"`
	List     string `json:"list"`
}

// GET USER INPUT
func getUserInput() (string, string, string, error) {
	reader := bufio.NewReader(os.Stdin)

	// USERNAME
	fmt.Print("Enter Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", "", "", fmt.Errorf("READING INPUT FOR USERNAME")
	}
	username = strings.TrimSpace(username)

	// PASSWORD
	fmt.Print("Enter Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", "", fmt.Errorf("READING INPUT FOR PASSWORD")
	}
	password := string(bytePassword)
	password = strings.TrimSpace(password)

	// CHECK USERNAME AND PASSWORD LENGHT
	if len(username) < 3 || len(password) < 3 {
		return "", "", "", fmt.Errorf("USERNAME AND PASSWORD MUST BE AT LEAST 3 CHARACTERS LONG")
	}

	// IP ADDRESS
	fmt.Print("\nEnter IP address: ")
	ipAddress, err := reader.ReadString('\n')
	if err != nil {
		return "", "", "", fmt.Errorf("READING INPUT FOR IP ADDRESS")
	}

	parsedIP := net.ParseIP(strings.TrimSpace(ipAddress))
	if parsedIP == nil {
		return "", "", "", fmt.Errorf("INVALID IP ADDRESS FORMAT")
	}

	ip4 := parsedIP.To4()
	if ip4 == nil {
		return "", "", "", fmt.Errorf("INVALID IP ADDRESS FORMAT")
	}

	return username, password, strings.TrimSpace(ipAddress), nil
}

// SETUP CLIENT
func setupClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	return client
}

// TEST LOGIN CREDENTIALS
func testLoginCredentials(username string, password string, ipAddress string) error {
	client := setupClient()

	req, _ := http.NewRequest("GET", "https://"+ipAddress+"/rest/system/resource", nil)
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP STATUS CODE " + strconv.Itoa(resp.StatusCode))
	}
	return nil
}

// GET BLACKLIST FROM TALOS URL
func getTalosData() (bufio.Scanner, error) {
	client := setupClient()

	req, _ := http.NewRequest("GET", talosURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return *bufio.NewScanner(bytes.NewReader(nil)), err
	}
	if resp.StatusCode != http.StatusOK {
		return *bufio.NewScanner(bytes.NewReader(nil)), fmt.Errorf("HTTP STATUS CODE " + strconv.Itoa(resp.StatusCode))
	}

	body, _ := ioutil.ReadAll(resp.Body)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	return *scanner, nil
}

func main() {
	// GET USER INPUT
	username, password, ipAddress, err := getUserInput()
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}

	// TEST LOGIN CREDENTIALS FOR PROVIDED IP
	err = testLoginCredentials(username, password, ipAddress)
	if err != nil {
		fmt.Println("Mikrotik login failed!")
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}

	// GET LATEST BLACKLIST FROM TALOS
	talosData, err := getTalosData()
	if err != nil {
		fmt.Println("Unable to get blacklist from TALOS!")
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}

	// UPLOAD BLACKLIST TO MIKROTIK
	client := setupClient()
	for talosData.Scan() {
		newIP := BlackList{
			IP:       talosData.Text(),
			Disabled: "false",
			Dynamic:  "false",
			List:     "TALOS_BLACKLIST",
		}

		// CONVERT GO VALUES INTO JSON, IF FAILS, EXIT PROGRAM
		dataBytes, err := json.Marshal(newIP)
		if err != nil {
			fmt.Println("ERROR:", err)
			os.Exit(1)
		}

		// UPLOAD IP TO MIKROTIK
		req, _ := http.NewRequest("PUT", "https://"+ipAddress+"/rest/ip/firewall/address-list", bytes.NewReader(dataBytes))
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.SetBasicAuth(username, password)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("IP:", talosData.Text(), "-ERROR:", err)
			continue
		}
		defer resp.Body.Close()

		// PRINT RESULT FOR EVERY IP
		fmt.Print("IP:", talosData.Text())
		fmt.Println("-Response Status:", resp.Status)
		fmt.Println("Response Headers:", resp.Header)
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("Response Body:", string(body))

	}
}
