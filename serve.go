package main

import (
	"fmt"
	"io/ioutil"
	"io"
	"log"
	"net/http"
	"regexp"
)

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func handler(w http.ResponseWriter, r *http.Request) {

	filename := r.URL.Path[1:]
	fmt.Println(filename)
	data, err := ioutil.ReadFile(filename)

	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	w.Header().Set("Content-Type", "text/html")
	w.Write(data)

}

func main() {

	var s http.ServeMux

	var cssPath = regexp.MustCompile("^/.*\\.css$")
	var htmlPath = regexp.MustCompile("^/.*\\.html$")
	var jsPath = regexp.MustCompile("^/.*\\.js$")
	var jsonPath = regexp.MustCompile("^/.*\\.json$")
	var woffPath = regexp.MustCompile("^/.*\\.woff2$")
	var svgPath = regexp.MustCompile("^/.*\\.svg$")
	var esPath = regexp.MustCompile("^/elasticsearch/")
	var gnPath = regexp.MustCompile("^/gaffer-net/")
	var grPath = regexp.MustCompile("^/gaffer-risk/")
	var gtPath = regexp.MustCompile("^/gaffer-threat/")

	s.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		
		if r.URL.Path == "/" { r.URL.Path = "/index.html" }

		fmt.Println(r.URL.Path)

		if m := cssPath.FindStringSubmatch(r.URL.Path); m != nil {
			w.Header().Set("Content-Type", "text/css")
			filename := r.URL.Path[1:]
			data, _ := ioutil.ReadFile(filename)
			w.Write(data)
			return
		}

		if m := htmlPath.FindStringSubmatch(r.URL.Path); m != nil {
			w.Header().Set("Content-Type", "text/html")
			filename := r.URL.Path[1:]
			data, _ := ioutil.ReadFile(filename)
			w.Write(data)
			return
		}

		if m := jsPath.FindStringSubmatch(r.URL.Path); m != nil {
			w.Header().Set("Content-Type", "text/javascript")
			filename := r.URL.Path[1:]
			data, _ := ioutil.ReadFile(filename)
			w.Write(data)
			return
		}

		if m := jsonPath.FindStringSubmatch(r.URL.Path); m != nil {
			w.Header().Set("Content-Type", "text/javascript")
			filename := r.URL.Path[1:]
			data, _ := ioutil.ReadFile(filename)
			w.Write(data)
			return
		}

		if m := woffPath.FindStringSubmatch(r.URL.Path); m != nil {
			w.Header().Set("Content-Type", "text/plain")
			filename := r.URL.Path[1:]
			data, _ := ioutil.ReadFile(filename)
			w.Write(data)
			return
		}

		if m := svgPath.FindStringSubmatch(r.URL.Path); m != nil {
			w.Header().Set("Content-Type", "text/xml+svg")
			filename := r.URL.Path[1:]
			data, _ := ioutil.ReadFile(filename)
			w.Write(data)
			return
		}

		if m := esPath.FindStringSubmatch(r.URL.Path); m != nil {

			path := r.URL.Path[15:]

			r.URL.Path = path
			r.URL.Host = "localhost:9200"
			r.URL.Scheme = "http"

			resp, err := http.DefaultTransport.RoundTrip(r)

			if err != nil {
				log.Printf("503: %s", err.Error())
				http.Error(w, err.Error(),
					http.StatusServiceUnavailable)
				return
			}

			defer resp.Body.Close()
			copyHeader(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			return

		}

		if m := gnPath.FindStringSubmatch(r.URL.Path); m != nil {

			path := r.URL.Path[11:]

			fmt.Println(path)

			r.URL.Path = path
			r.URL.Host = "localhost:8088"
			r.URL.Scheme = "http"

			resp, err := http.DefaultTransport.RoundTrip(r)

			if err != nil {
				log.Printf("503: %s", err.Error())
				http.Error(w, err.Error(),
					http.StatusServiceUnavailable)
				return
			}

			defer resp.Body.Close()
			copyHeader(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			return

		}

		if m := grPath.FindStringSubmatch(r.URL.Path); m != nil {

			path := r.URL.Path[12:]

			fmt.Println(path)

			r.URL.Path = path
			r.URL.Host = "localhost:8089"
			r.URL.Scheme = "http"

			resp, err := http.DefaultTransport.RoundTrip(r)

			if err != nil {
				log.Printf("503: %s", err.Error())
				http.Error(w, err.Error(),
					http.StatusServiceUnavailable)
				return
			}

			defer resp.Body.Close()
			copyHeader(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			return

		}

		if m := gtPath.FindStringSubmatch(r.URL.Path); m != nil {

			path := r.URL.Path[14:]

			fmt.Println(path)

			r.URL.Path = path
			r.URL.Host = "localhost:8090"
			r.URL.Scheme = "http"

			resp, err := http.DefaultTransport.RoundTrip(r)

			if err != nil {
				log.Printf("503: %s", err.Error())
				http.Error(w, err.Error(),
					http.StatusServiceUnavailable)
				return
			}

			defer resp.Body.Close()
			copyHeader(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			return

		}
								
		http.NotFound(w, r)
		return
	})

	log.Fatal(http.ListenAndServe(":8080", &s))

}
