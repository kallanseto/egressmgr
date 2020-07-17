package main

import (
        "bytes"
        "crypto/tls"
        "crypto/x509"
        "encoding/json"
        "errors"
        "fmt"
        "io"
        "io/ioutil"
        "net/http"
        "time"

        "github.com/labstack/echo"
        "github.com/labstack/echo/middleware"
)

// Global environment variables
var kubeapi = "https://kubernetes.default.svc/"
var apipath = "apis/network.openshift.io/v1/netnamespaces/"

type serverAddressRecord struct {
        ServerAddress string `json:"serverAddress"`
}

type apiVersions struct {
        ServerAddressByClientCIDRs []serverAddressRecord `json:"serverAddressByClientCIDRs"`
}

type netNamespace struct {
        Netname   string   `json:"netname"`
        EgressIPs []string `json:"egressIPs"`
}

type egressResult struct {
        Timestamp string `json:"timestamp"`
        Namespace string `json:"namespace"`
        EgressIP  string `json:"egressip"`
        Message   string `json:"message"`
}

func kubeapiRequest(method, url string, body io.Reader) (*http.Response, error) {
        // Get the API token from the serviceaccount
        b, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
        if err != nil {
                fmt.Print(err)
        }
        apiToken := string(b)

        // Set the Authorization Header
        req, err := http.NewRequest(method, url, body)
        if err != nil {
                fmt.Print(err)
        }
        req.Header.Set("Authorization", "Bearer "+apiToken)

        if method == "PATCH" {
                req.Header.Add("Content-Type", "application/strategic-merge-patch+json")
        }

        caCert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
        if err != nil {
                fmt.Print(err)
        }

        caCertPool := x509.NewCertPool()
        caCertPool.AppendCertsFromPEM(caCert)

        // Setup HTTPS client
        tlsConfig := &tls.Config{
                RootCAs: caCertPool,
        }
        transport := &http.Transport{TLSClientConfig: tlsConfig}
        client := &http.Client{Transport: transport}

        return client.Do(req)
}

func getThisCluster(c echo.Context) error {
        resp, err := kubeapiRequest("GET", kubeapi+"api", nil)
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        b, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                fmt.Print(err)
        }

        a := apiVersions{}

        err = json.Unmarshal(b, &a)
        if err != nil {
                fmt.Println(err)
        }

        return c.JSON(http.StatusOK, a.ServerAddressByClientCIDRs[0].ServerAddress)
}

func checkEgressIP(netnamespace string) (string, error) {
        resp, err := kubeapiRequest("GET", kubeapi+apipath+netnamespace, nil)
        if err != nil {
                return "", err
        }
        defer resp.Body.Close()

        b, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                fmt.Print(err)
        }

        // If kubeapiRequest was successful but some other error (e.g. unauthorized, not found), return empty string
        if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
                return "", errors.New("API server returned " + resp.Status)
        }

        n := netNamespace{}

        err = json.Unmarshal(b, &n)
        if err != nil {
                fmt.Println(err)
        }

        if n.EgressIPs == nil {
                return "", err
        } else {
                return n.EgressIPs[0], err
        }
}

func getEgressIP(c echo.Context) error {
        n := c.Param("n")
        e, err := checkEgressIP(n)

        r := &egressResult{
                Timestamp: time.Now().In(time.Local).String(),
                Namespace: n,
                EgressIP:  e,
                Message:   "Success",
        }

        if err != nil {
                r.Message = "Error: " + err.Error()
                return c.JSON(http.StatusInternalServerError, r)
        }

        return c.JSON(http.StatusOK, r)
}

func assignEgressIP(c echo.Context) error {
        n := c.Param("n")
        e := c.Param("e")

        // Check if egressIP has already been assigned
        currentegress, err := checkEgressIP(n)

        r := &egressResult{
                Timestamp: time.Now().In(time.Local).String(),
                Namespace: n,
                EgressIP:  currentegress,
                Message:   "Success",
        }

        // Handle if something went wrong with the internal API call or didn't get 200 response
        if err != nil {
                r.Message = "Error: " + err.Error()
                return c.JSON(http.StatusInternalServerError, r)
        }

        // Handle egressIP already assigned
        if currentegress != "" {
                r.Message = "Failed: Namespace already has egressIP assigned"
                return c.JSON(http.StatusInternalServerError, r)
        }

        // Let's assign the egressIP!
        patchdata := []byte(`{"egressIPs": ["` + e + `"]}`)

        resp, err := kubeapiRequest("PATCH", kubeapi+apipath+n, bytes.NewBuffer(patchdata))
        if err != nil {
                r.Message = "Error: " + err.Error()
                return c.JSON(http.StatusInternalServerError, r)
        }
        defer resp.Body.Close()

        b, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                fmt.Print(err)
        }

        // If kubeapiRequest was successful but some other error (e.g. unauthorized, not found)
        if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
                r.Message = "Error: " + "API server returned " + resp.Status
                return c.JSON(http.StatusInternalServerError, r)
        }

        nn := netNamespace{}

        err = json.Unmarshal(b, &nn)
        if err != nil {
                fmt.Print(err)
        }

        r.EgressIP = e
        if nn.EgressIPs[0] == e {
                return c.JSON(http.StatusCreated, r)
        } else {
                r.Message = "Error: Something has gone wrong. Please contact cluster adminstrator"
                return c.JSON(http.StatusInternalServerError, r)
        }

}

func main() {
        e := echo.New()
        e.Use(middleware.Logger())

        e.GET("/thiscluster", getThisCluster)
        e.GET("/:n", getEgressIP)
        e.POST("/assign/:n/:e", assignEgressIP)

        e.Logger.Fatal(e.Start(":8080"))
}
