package main

import (
	"fmt"

	"github.com/divyag9/etcdpitch/packages/client"
)

func main() {
	etcd, err := client.NewEtcd("etcd", "tcp", "sgtec.io", "C:/Safeguard/AppCerts/Default/default.cer", "C:/Safeguard/AppCerts/Default/default.key")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	err = client.SetEtcdKey(etcd, "/TestGo/31330BFE98440A1D47E4639CAB6918AD454946F5/Test", "GO")
	if err != nil {
		fmt.Println("Error: ", err)
	}

	value, err := client.GetEtcdValue(etcd, "/TestGo/31330BFE98440A1D47E4639CAB6918AD454946F5/Test")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Println("Decrypted value: ", value)
}
