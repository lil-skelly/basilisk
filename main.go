package main

import (
    "fmt"
	"net/http"
	"io/ioutil"
    "time"
    "flag"
)

var (
    kingFilePath string
    interval     time.Duration
)


func init() {
    flag.StringVar(&kingFilePath, "file", "king.txt", "Path to the king file")
    flag.DurationVar(&interval, "interval", 5*time.Second, "Time interval between requests (e.g., 1s..5s)")
}

func main() {
    flag.Parse()

    fmt.Println("++ Welcome to TryHackMe KoTH ++")
    fmt.Println("==> Serving KoTH service at :9999 <==")
    http.HandleFunc("/", returnKing) // Home route (/) calls returnKing 
    go func() {
        if err := http.ListenAndServe(":9999", nil); err != nil {
            fmt.Println("Error starting server:", err)
        }
    }()
    go simulateKingReadWeb()
    select {}
}

func returnKing(w http.ResponseWriter, r *http.Request) {
    w.Write(readKing()) // Writes the results of readKing() to the web page
}

func readKing() []byte{
	buff, err := ioutil.ReadFile(kingFilePath) // Read the file /root/king.txt
	if err != nil { // Error handling
		fmt.Println(err.Error())
        exit(1)
	}
	return buff // Return data from /root/king.txt
}

func simulateKingReadWeb() {
    client := &http.Client{}
    for {
        currentTime := time.Now()
        resp, err := client.Get("http://localhost:9999/")
        if err != nil {
            fmt.Printf("[%s] Error making request: %s\n", currentTime.Format("15:04:05"), err)
        } else {
            body, _ := ioutil.ReadAll(resp.Body) // Read the response body
            resp.Body.Close()                    // Close the response body

            fmt.Printf("[%s] Current king => %s\n", currentTime.Format("15:04:05"), body)
        }
        time.Sleep(interval)
    }
}