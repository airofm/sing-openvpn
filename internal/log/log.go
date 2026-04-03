package log

import (
	"log"
)

func Infoln(format string, v ...interface{}) {
	log.Printf("[INFO] "+format+"\n", v...)
}

func Warnln(format string, v ...interface{}) {
	log.Printf("[WARN] "+format+"\n", v...)
}

func Debugln(format string, v ...interface{}) {
	// log.Printf("[DEBUG] " + format + "\n", v...)
}

func Errorln(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format+"\n", v...)
}
