package main

import (
    "fmt"
    "net/http"
    "strings"
    "log"
    "io/ioutil"
)

var not_found_page string

func respond(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Path
    if len(file) == 0 || file == "/" {
        file = "/home.html"    
    }

    content, err := ioutil.ReadFile(file[1:])
	if err != nil {

		w.Write([]byte(strings.Replace(not_found_page, "${content}", r.URL.Path[1:], -1)))

	} else if file == "/home.html" {

        var headers string

        for k, v := range r.Header {
            if k[0:1] == "X" {
                headers = headers + "<tr><th>" + k + "</th><td>" + strings.Join(v,"<br>") + "</td></tr>"
            }
        }

		w.Write([]byte(strings.Replace(string(content), "${content}", headers, -1)))

    } else {

        w.Write(content)

    }
}


func main() {
    
    not_found_page_bytes, err := ioutil.ReadFile("404.html")
	if err != nil {
		fmt.Println(err)
		return
	}
    not_found_page = string(not_found_page_bytes)

    http.HandleFunc("/", respond) // set router
    err = http.ListenAndServe(":9090", nil) // set listen port
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
