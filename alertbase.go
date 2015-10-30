package main


import (
	"github.com/LDCS/sflag"
	"github.com/LDCS/genutil"
	"github.com/LDCS/cim"
	"github.com/LDCS/alertbaseutil"
	"fmt"
	"os"
	"encoding/json"
	"strings"
	"log"
	"time"
	"sort"
	"bufio"
	"path"
)


var opt = struct{
	Usage        string    "Alerts database"
	Inst         string    "Instance number|01"
	Logdir       string    "Log dir|./"
	Logfile      string    "Log file|alertbase.20060102.log"
	Alertsfile   string    "hcsv file where alerts are stored|./alerts.csv"
	Opsfile      string    "headerless csv file where each takeover is recorded|./ops.csv"
}{}

var lg *log.Logger = nil


type CHANROWS struct {
	Retchan chan []*alertbaseutil.ROW
}

type CHANOPSROWS struct {
	Retchan chan []*alertbaseutil.OPSROW
}

type ABChans struct {  // Set of all chans used by alertbase
	addModRowChan   chan alertbaseutil.ROW
	getListChan     chan CHANROWS
	addOpsRowChan   chan alertbaseutil.OPSROW
	getOpsListChan  chan CHANOPSROWS
}


func manageDB() {
	var chanStruct = ABChans{
		addModRowChan   : make(chan alertbaseutil.ROW),
		getListChan     : make(chan CHANROWS),
		addOpsRowChan   : make(chan alertbaseutil.OPSROW),
		getOpsListChan  : make(chan CHANOPSROWS),
	}
	var db = map[int64]*alertbaseutil.ROW{}
	var sortedRows = []*alertbaseutil.ROW{}
	var opsarr = make([]*alertbaseutil.OPSROW, 15) // Remember only last 15 takeovers
	var fp *os.File = nil
	var fpops *os.File = nil
	lg.Println("manageDB : starting up...")
	if _, err := os.Stat(opt.Alertsfile); err != nil {
		fp, err = os.Create(opt.Alertsfile)
		if err != nil {
			lg.Println("manageDB : cannot create alertsfile =", opt.Alertsfile, "err =", err, "Exiting...")
			os.Exit(1)
		}
		fp.WriteString((&alertbaseutil.ROW{}).GetHeader() + "\n")
		fp.Sync()
	} else {
		fp, err = os.OpenFile(opt.Alertsfile, os.O_RDWR|os.O_APPEND, 0755)
		if err != nil {
			lg.Println("manageDB : cannot open alertsfile =", opt.Alertsfile, "err =", err, "Exiting...")
			os.Exit(1)
		}
	}
	lg.Println("manageDB : Opened alertfile =", opt.Alertsfile)
	defer fp.Close()
	if _, err := os.Stat(opt.Opsfile); err != nil {
		fpops, err = os.Create(opt.Opsfile)
		if err != nil {
			lg.Println("manageDB : cannot create opsfile =", opt.Opsfile, "err =", err, "Exiting...")
			os.Exit(1)
		}
	} else {
		fpops, err = os.OpenFile(opt.Opsfile, os.O_RDWR|os.O_APPEND, 0755)
		if err != nil {
			lg.Println("manageDB : cannot open opsfile =", opt.Opsfile, "err =", err, "Exiting...")
			os.Exit(1)
		}
	}
	lg.Println("manageDB : Opened opsfile =", opt.Opsfile)
	defer fpops.Close()
	scanner := bufio.NewScanner(fp)
	lineno := 1
	for scanner.Scan() {
		if lineno == 1 {
			lineno += 1
			continue
		}
		row := new(alertbaseutil.ROW)
		err1 := row.SetFromCSV(scanner.Text())
		if err1 != nil {
			lg.Println("manageDB : Found bad csv line at line number =", lineno, "err =", err1 )
			lineno += 1
			continue
		}
		key := row.GetKey()
		if key < int64(0) {
			lg.Println("manageDB : Found alert with bad key at line number =", lineno )
			lineno += 1
			continue
		}
		if row.IsOlderThan(4*24*time.Hour) {
			lineno += 1
			continue
		}
		db[key] = row
		lineno += 1
	}
	if err := scanner.Err(); err != nil {
		lg.Println("manageDB : Error reading alertsfile =", opt.Alertsfile, "err =", err, "Will continue anyway...")
	}

	sortedRows = make([]*alertbaseutil.ROW, len(db))
	ii := 0
	for _, vv := range db { sortedRows[ii] = vv; ii += 1 }
	sort.Sort(alertbaseutil.ROWS(sortedRows))

	// Load last 15 lines from opsfile
	out := strings.Trim(genutil.BashExecOrDie(false, "/usr/bin/tail -15 " + opt.Opsfile + " | /usr/bin/tac", path.Dir(opt.Opsfile)), " \r\t\n")
	numopsrows := 0
	if out != "" {
		lines := strings.Split(out, "\n")
		idx := 14
		for ii := 0; ii < len(lines); ii++ {
			row := new(alertbaseutil.OPSROW)
			line := lines[len(lines) - ii - 1]
			errrow := row.SetFromCSV(strings.Trim(line, " \t\r\n"))
			if errrow != nil {
				continue
			}
			opsarr[idx] = row
			idx -= 1
			numopsrows += 1
		}
	}

	go startCimServer(&chanStruct)
	lg.Println("manageDB : started cim server")
	lg.Println("manageDB : starting event loop")
	for {
		var row = alertbaseutil.ROW{}
		select {
		case row = <-(chanStruct.addModRowChan):
			rowptr := &row
			lg.Println("manageDB : Got an alert from outside row =", row)
			key := rowptr.GetKey()
			if key < int64(0) {
				lg.Println("manageDB : But this alert has bad openat. Doing nothing")
				continue
			}
			if rowptr.IsOlderThan(4*24*time.Hour) {
				lg.Println("manageDB : But this alert is too old. Doing nothing")
			}
			rowInDb, ok := db[key]
			if !ok {
				lg.Println("manageDB : This alert is not present in the db, so adding")
				db[key] = rowptr
				fp.WriteString(rowptr.GetCSV() + "\n")
				fp.Sync()
			} else {
				rowInDb.UpdateWith(rowptr)
				fp.WriteString(rowInDb.GetCSV() + "\n")
				fp.Sync()
			}
			// remove old ones
			for kk, vv := range db {
				if vv.IsOlderThan(4*24*time.Hour)  { delete(db, kk) }
			}
			sortedRows = make([]*alertbaseutil.ROW, len(db))
			ii := 0
			for _, vv := range db { sortedRows[ii] = vv; ii+=1 }
			sort.Sort(alertbaseutil.ROWS(sortedRows))
			
		case chanrows := <-(chanStruct.getListChan):
			chanrows.Retchan <- sortedRows
		case opsrowtmp := <-(chanStruct.addOpsRowChan):
			opsrowptr := &opsrowtmp
			lg.Println("manageDB : Got an ops row from outside : row =", opsrowtmp)
			if numopsrows < 15 {
				opsarr[14 - numopsrows] = opsrowptr
				numopsrows += 1
			} else {
				numopsrows = 15
				for ii := 13; ii >= 0; ii-- {
					opsarr[ii+1] = opsarr[ii]
				}
				opsarr[0] = opsrowptr
			}
			fpops.WriteString(opsrowptr.GetCSV() + "\n")
			fpops.Sync()
		case chanopsrows := <-(chanStruct.getOpsListChan):
			chanopsrows.Retchan <- opsarr[15-numopsrows:15]
		}
	}
}


func editAlert(data interface{}, cmd string, args ...string) string {
	cs := data.(*ABChans)
	if cmd != "editalert" { return "" }
	if len(args) < 1 { return "No alert kvplist provided" }
	row := new(alertbaseutil.ROW)
	row.SetFromKVL(strings.Join(args, " "))
	cs.addModRowChan <- *row
	return "done"
}

func addOps(data interface{}, cmd string, args ...string) string {
	cs := data.(*ABChans)
	if cmd != "addops" { return "" }
	if len(args) < 1 { return "No ops row csv provided" }
	row := new(alertbaseutil.OPSROW)
	row.SetFromCSV(strings.Join(args, " "))
	cs.addOpsRowChan <- *row
	return "done"
}

func getAllJSON(data interface{}, cmd string, args ...string) string {
	cs := data.(*ABChans)
	if cmd != "getalljson" { return "" }
	chanrows := CHANROWS{ Retchan : make(chan []*alertbaseutil.ROW)}
	cs.getListChan <- chanrows
	sortedRows := <-(chanrows.Retchan)
	numrows := len(sortedRows)
	if numrows > 100 { numrows = 100 } // Limit number of recent alerts to 100
	buf, _ := json.Marshal(sortedRows[0:numrows])
	return string(buf)
}

func getAllOpsJSON(data interface{}, cmd string, args ...string) string {
	cs := data.(*ABChans)
	if cmd != "getallopsjson" { return "" }
	chanrows := CHANOPSROWS{ Retchan : make(chan []*alertbaseutil.OPSROW)}
	cs.getOpsListChan <- chanrows
	opsrows := <-(chanrows.Retchan)
	buf, _ := json.MarshalIndent(opsrows, "", "  ")
	return string(buf)
}

func startCimServer(cs *ABChans) {
	cn := new(cim.CimNode)
	cn.IsLeaf = true
	cn.Name = "/"
	cn.Path = "/"
	cn.Children = []*cim.CimNode{}
	cn.Callbacks = make(map[string]cim.CBfunc)
	cn.Callbacks["editalert"] = editAlert
	cn.Callbacks["getalljson"] = getAllJSON
	cn.Callbacks["addops"] = addOps
	cn.Callbacks["getallopsjson"] = getAllOpsJSON
	hostname,_ := os.Hostname()
	csrv, err := cim.NewCimServer(hostname, "alertbase" + opt.Inst, cn, cs)
	if err != nil {
		fmt.Println("Cim server failed to start")
		fmt.Println(err)
		return
	}
	csrv.Start()
}
 

func main() {

	sflag.Parse(&opt)
	var err error = nil
	lg, err = genutil.SetupLogger(fmt.Sprintf("%s/%s", opt.Logdir, time.Now().Format(opt.Logfile)), " Alertbase ")
	if err != nil {
		log.Println("Error setting up the log file err =", err)
		return
	}
	manageDB()
}
