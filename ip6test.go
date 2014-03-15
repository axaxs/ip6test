package main

import (
	"bufio"
	"fmt"
	"github.com/axaxs/aasemail"
	"github.com/axaxs/ip6monitor"
	"html"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const LISTENPORT = "5555"

var (
	//File mutex
	mtf sync.Mutex
	//Running list mutex
	mtl sync.Mutex
	//Error list mutex
	mte sync.Mutex
	//our list of test, well, pointers to them
	testlist = make([]*ip6test, 0)
	//list of recent failures
	recentfailures = make([]string, 0, 50)
)

type tester interface {
	Test() (bool, string, error)
}

type ip6test struct {
	montype     string
	id          string
	description string
	interval    int
	retry       int
	emaillist   string
	server      string
	atest       tester
	encoded     string
}

func randstring(length int) string {
	rand.Seed(time.Now().UnixNano())
	res := make([]byte, length)
	chars := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	for i := 0; i < len(res); i++ {
		randno := rand.Intn(len(chars))
		ind := randno % (len(chars) - 1)
		res[i] = chars[ind]
	}
	result := string(res)
	for _, v := range testlist {
		if v.id == result {
			result = randstring(length)
		}
	}
	return result
}

func storeMonitor(kvmap url.Values) (string, error) {
	monid := kvmap.Get("id")
	var err error
	if monid == "" {
		//lock list so we can make sure id is not taken
		mtl.Lock()
		monid = randstring(5)
		mtl.Unlock()
		//lock file operations while we store this
		mtf.Lock()
		defer mtf.Unlock()
		newIndex := fmt.Sprintf("%s||%s||%s", monid, kvmap.Get("type"), url.QueryEscape(kvmap.Get("description")))
		f, err := os.OpenFile("monitors.index", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Println(err)
			return monid, err
		}
		defer f.Close()
		_, err = f.Write([]byte(newIndex + "\n"))
		if err != nil {
			log.Println(err)
			return monid, err
		}
	} else {
		newIndex := fmt.Sprintf("%s||%s||%s", monid, kvmap.Get("type"), url.QueryEscape(kvmap.Get("description")))
		err = replaceIndex(monid, newIndex)
		if err != nil {
			log.Println(err)
			mover()
			return monid, err
		}
		err = mover()
		if err != nil {
			log.Println(err)
			return monid, err
		}
	}
	_ = os.Mkdir("monitors", 0755)
	g, err := os.Create("monitors/" + monid)
	if err != nil {
		log.Println(err)
		return monid, err
	}
	defer g.Close()
	_, err = g.Write([]byte(kvmap.Encode()))
	return monid, err
}

func loadMonitors() error {
	f, err := os.Open("monitors.index")
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			return nil
		}
		log.Println(err)
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		monitor, err := buildMonFromFile(sc.Text())
		if err == nil {
			testlist = append(testlist, monitor)
		} else {
			log.Println(err)
		}
	}
	if err = sc.Err(); err != nil {
		log.Println(err)
		return err
	}
	return err
}

func buildMonFromFile(ins string) (*ip6test, error) {
	var err error
	spl := strings.Split(ins, "||")
	monid := spl[0]
	f, err := ioutil.ReadFile("monitors/" + monid)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	kvmap, err := url.ParseQuery(strings.TrimSpace(string(f)))
	if err != nil {
		return nil, err
	}
	test, err := buildMon(kvmap)
	test.id = monid
	return test, err
}

func buildMon(kvmap url.Values) (*ip6test, error) {
	var test *ip6test
	var err error
	switch strings.ToUpper(kvmap.Get("type")) {
	case "DNS":
		test, err = dnsMon(kvmap)
	case "HTTP":
		test, err = httpMon(kvmap)
	case "TCP":
		test, err = tcpMon(kvmap)
	case "PING":
		test, err = pingMon(kvmap)
	default:
		err = fmt.Errorf("Type %s not recognized!", kvmap.Get("type"))
	}
	if err != nil {
		log.Println(err)
		return nil, err
	}
	test.id = kvmap.Get("id")
	test.description = kvmap.Get("description")
	test.montype = kvmap.Get("type")
	test.emaillist = strings.Replace(kvmap.Get("email"), " ", "", -1)
	test.encoded = kvmap.Encode()
	return test, err
}

func dnsMon(ins url.Values) (*ip6test, error) {
	var err error
	mon := new(ip6test)
	_, k1 := ins["interval"]
	_, k2 := ins["retrycount"]
	_, k3 := ins["host"]
	_, k4 := ins["recordtype"]
	_, k5 := ins["email"]
	if !k1 || !k2 || !k3 || !k4 || !k5 {
		return nil, fmt.Errorf("Invalid request parameters!")
	}
	mon.server = ins.Get("host")
	mon.interval, err = strconv.Atoi(ins.Get("interval"))
	if err != nil {
		return nil, err
	}
	mon.retry, err = strconv.Atoi(ins.Get("retrycount"))
	if err != nil {
		return nil, err
	}
	atest := ip6monitor.NewDnsTest(ins.Get("host"), ins.Get("recordtype"))
	atest.SetHost(ins.Get("server"))
	atest.SetAnswer(ins.Get("checkfor"))
	mon.atest = atest
	log.Printf("Successfully parsed dnsMonitor %s against '%s'", ins.Get("id"), ins.Get("host"))
	return mon, err
}

func httpMon(ins url.Values) (*ip6test, error) {
	var err error
	mon := new(ip6test)
	_, k1 := ins["interval"]
	_, k2 := ins["retrycount"]
	_, k3 := ins["url"]
	_, k4 := ins["email"]
	if !k1 || !k2 || !k3 || !k4 {
		return nil, fmt.Errorf("Invalid request parameters!")
	}
	mon.server = ins.Get("url")
	mon.interval, err = strconv.Atoi(ins.Get("interval"))
	if err != nil {
		return nil, err
	}
	mon.retry, err = strconv.Atoi(ins.Get("retrycount"))
	if err != nil {
		return nil, err
	}
	atest := ip6monitor.NewHttpTest(ins.Get("url"))
	err = atest.SetIP(ins.Get("host"))
	if err != nil {
		return nil, err
	}
	atest.SetToken(ins.Get("searchfor"))
	atest.SetPostData(ins.Get("data"))
	mon.atest = atest
	log.Printf("Successfully parsed httpMonitor %s against '%s'", ins.Get("id"), ins.Get("url"))
	return mon, err
}

func tcpMon(ins url.Values) (*ip6test, error) {
	var err error
	mon := new(ip6test)
	_, k1 := ins["interval"]
	_, k2 := ins["retrycount"]
	_, k3 := ins["host"]
	_, k4 := ins["port"]
	_, k5 := ins["email"]
	if !k1 || !k2 || !k3 || !k4 || !k5 {
		return nil, fmt.Errorf("Invalid request parameters!")
	}
	mon.server = ins.Get("host")
	mon.interval, err = strconv.Atoi(ins.Get("interval"))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	mon.retry, err = strconv.Atoi(ins.Get("retrycount"))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	atest := ip6monitor.NewTcpTest(ins.Get("host"), ins.Get("port"))
	atest.SetToken(ins.Get("searchfor"))
	if ins.Get("tls") != "" {
		atest.SetTls("certs/pub.pem", "certs/priv.pem")
	}
	atest.SetSendData(strings.Replace(ins.Get("data"), "<br>", "\r\n", -1))
	mon.atest = atest
	log.Printf("Successfully parsed tcpMonitor %s against '%s'", ins.Get("id"), ins.Get("host"))
	return mon, err
}

func pingMon(ins url.Values) (*ip6test, error) {
	var err error
	mon := new(ip6test)
	_, k1 := ins["interval"]
	_, k2 := ins["retrycount"]
	_, k3 := ins["host"]
	if !k1 || !k2 || !k3 {
		log.Println("Invalid request parameters supplied to pingmon")
		return nil, fmt.Errorf("Invalid request parameters!")
	}
	mon.server = ins.Get("host")
	mon.interval, err = strconv.Atoi(ins.Get("interval"))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	mon.retry, err = strconv.Atoi(ins.Get("retrycount"))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	mon.atest = ip6monitor.NewPingTest(ins.Get("host"))
	log.Printf("Successfully parsed pingMonitor %s against '%s'\n", ins.Get("id"), ins.Get("host"))
	return mon, err
}

func testNet() bool {
	log.Println("Testing network google.com to make sure internet works before calling failure")
	c, err := net.DialTimeout("tcp6", "www.google.com:80", 3*time.Second)
	if err != nil {
		log.Println("Google failed, testing yahoo.com...")
		c, err = net.DialTimeout("tcp6", "www.yahoo.com:80", 3*time.Second)
		if err != nil {
			log.Println("Google and Yahoo failed.  Assuming problem is on my end")
			return false
		}
		c.Close()
		log.Println("Yahoo works, assuming internet is good")
		return true
	}
	c.Close()
	log.Println("Google works, assuming internet is good")
	return true
}

func (t *ip6test) startTest(limchan chan bool) {
	var good bool
	var err error
	var sdata string
	for i := 0; i <= t.retry; i++ {
		log.Printf("Starting test \"%s\", attempt %d\n", t.description, i+1)
		good, sdata, err = t.atest.Test()
		if good {
			log.Printf("Test \"%s\" completed successfully\n", t.description)
			limchan <- true
			return
		}
		if !testNet() {
			i--
			time.Sleep(10 * time.Second)
		}
		time.Sleep(5 * time.Second)
	}
	log.Printf("Test %s \"%s\" has failed\n", t.id, t.description)
	tnow := time.Now().Format("2006-01-02 15:04:05")
	logError(fmt.Sprintf("%s||%s||%s||%s||%s", tnow, t.id, t.montype, t.server, err.Error()))
	em := aasemail.NewEmail()
	em.To = strings.Split(t.emaillist, ",")
	em.Subject = "IPv6 Monitor Failure - " + t.server
	em.Body = fmt.Sprintf("Error - %s monitor '%s' failed with error: \n %s\n\nReturn value was: \n\n%s", t.montype, t.description, err.Error(), sdata)
	em.From = "from@address"
	em.FromName = "FromName"
	em.Username = "userID"
	em.Password = "password"
	em.Server = "smtp.gmail.com"
	em.Port = "587"
	for emtries := 0; emtries < 5; emtries++ {
		err = em.Send()
		if err == nil {
			break
		}
		if emtries == 4 {
			log.Printf("Emailing failed with error: %s", err.Error())
			break
		}
		time.Sleep(15 * time.Second)
	}
	limchan <- true
}

func logError(ins string) {
	mte.Lock()
	defer mte.Unlock()
	recentfailures = append(recentfailures, ins)
	if len(recentfailures) > 49 {
		recentfailures = recentfailures[1:len(recentfailures)]
	}
	ioutil.WriteFile("recentFailures.txt", []byte(strings.Join(recentfailures, "\n")), 0644)
}

func loadErrors() {
	mte.Lock()
	defer mte.Unlock()
	d, err := ioutil.ReadFile("recentFailures.txt")
	if err != nil {
		log.Println(err)
		return
	}
	recentfailures = strings.Split(string(d), "\n")
}

func (t *ip6test) testOnce() (bool, string, error) {
	return t.atest.Test()
}

func startMonitoring() {
	limchan := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		limchan <- true
	}
	for {
		mtl.Lock()
		tem := make([]*ip6test, len(testlist))
		copy(tem, testlist)
		mtl.Unlock()
		minute := time.Now().Minute()
		if minute == 0 {
			minute = 60
		}
		for _, v := range tem {
			if minute%v.interval == 0 {
				<-limchan
				go v.startTest(limchan)
			}
		}
		time.Sleep(time.Duration(60-time.Now().Second()) * time.Second)
	}
}

func newMonitor(r *http.Request) string {
	err := r.ParseForm()
	if err != nil {
		log.Println("Error parsing formData!")
		return ("Error parsing formData!")
	}
	pdata := r.PostForm
	t, err := buildMon(pdata)
	if err != nil {
		return err.Error()
	}
	good, sdata, err := t.testOnce()
	if !good {
		log.Println("Error! First test failed! " + err.Error())
		return fmt.Sprintf("Error! First test failed!<br><br>%s<br><br>Return value was:<br>%s", err.Error(), html.EscapeString(sdata))
	}
	t.id, err = storeMonitor(pdata)
	if err != nil {
		log.Println("Error! " + err.Error())
		return "Error! " + err.Error()
	}
	mtl.Lock()
	defer mtl.Unlock()
	if pdata.Get("id") != "" {
		for i := range testlist {
			if testlist[i].id == pdata.Get("id") {
				testlist[i] = t
				return "Monitor successfully updated!"
			}
		}
	} else {
		testlist = append(testlist, t)
		return "Monitor successfully added!"
	}
	return "Id not found, no action taken!"
}

func getMonitor(r *http.Request) string {
	err := r.ParseForm()
	if err != nil {
		return ("Error parsing formData!")
	}
	pdata := r.PostForm
	idToGet := pdata.Get("id")
	if idToGet == "" {
		return "Error, id not specified!"
	}
	for _, v := range testlist {
		if v.id == idToGet {
			return v.encoded
		}
	}
	return fmt.Sprintf("Error - id %s not found in test list!", idToGet)
}

func mover() error {
	mtf.Lock()
	defer mtf.Unlock()
	//This is ugly.  I want to defer close, but need to rename file.  Sigh.
	err := os.Rename("monitors.index2", "monitors.index")
	return err
}

func replaceIndex(id, replacementline string) error {
	mtf.Lock()
	defer mtf.Unlock()
	f, err := os.Open("monitors.index")
	if err != nil {
		log.Println(err)
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	ff, err := os.Create("monitors.index2")
	if err != nil {
		log.Println(err)
		return err
	}
	defer ff.Close()
	wr := bufio.NewWriter(ff)
	found := false
	for sc.Scan() {
		lin := sc.Text()
		if strings.Split(lin, "||")[0] != id {
			_, err = wr.Write([]byte(lin + "\n"))
			if err != nil {
				log.Println(err)
				return err
			}
		} else {
			if replacementline != "" {
				_, err = wr.Write([]byte(replacementline + "\n"))
				if err != nil {
					log.Println(err)
					return err
				}
			}
			found = true
		}
	}
	err = wr.Flush()
	if err != nil {
		log.Println(err)
		return err
	}
	if err = sc.Err(); err != nil {
		log.Println(err)
		return err
	}
	if !found {
		return fmt.Errorf("Error, id not found in directory!")
	}
	return nil
}

func deleteMonitor(r *http.Request) string {
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		return ("Error parsing formData!")
	}
	pdata := r.PostForm
	idToDelete := pdata.Get("id")
	mtl.Lock()
	defer mtl.Unlock()
	found := false
	newlist := make([]*ip6test, 0, len(testlist)-1)
	for _, v := range testlist {
		if v.id != idToDelete {
			newlist = append(newlist, v)
		} else {
			found = true
		}
	}
	if !found {
		return "Error, id not found in testlist!"
	}
	testlist = newlist
	err = replaceIndex(idToDelete, "")
	if err != nil {
		log.Println(err)
		mover()
		return err.Error()
	}
	err = mover()
	if err != nil {
		log.Println(err)
		return err.Error()
	}
	err = os.Remove("monitors/" + idToDelete)
	if err != nil {
		log.Println(err)
		return "Error, could not delete file!" + err.Error()
	}
	return "Delete successful"
}

func listMonitors() string {
	res := ""
	for _, v := range testlist {
		res += fmt.Sprintf("%s||%s||%s||%d||%s\n", v.id, v.montype, v.server, v.interval, v.description)
	}
	return res
}

func recentFailures() string {
	return strings.Join(recentfailures, "\n")
}

func handler(w http.ResponseWriter, r *http.Request) {
	var resp string
	path := r.URL.Path
	switch path {
	case "/newMonitor":
		resp = newMonitor(r)
	case "/listMonitors":
		resp = listMonitors()
	case "/recentFailures":
		resp = recentFailures()
	case "/deleteMonitor":
		resp = deleteMonitor(r)
	case "/getMonitor":
		resp = getMonitor(r)
	default:
		resp = ""
	}
	w.Header().Add("Content-Type", "text/plain")
	w.Header().Add("Content-Length", strconv.Itoa(len(resp)))
	w.Header().Add("Connection", "close")
	w.Write([]byte(resp))
}

func main() {
	f, err := os.OpenFile("ip6test.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer f.Close()
	log.SetOutput(f)
	err = loadMonitors()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	loadErrors()
	go startMonitoring()
	http.HandleFunc("/", handler)
	http.ListenAndServe(":"+LISTENPORT, nil)
}
