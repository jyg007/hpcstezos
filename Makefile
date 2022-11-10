all: createtezoskey importtzsk2hsm gentzkeyfromhsmsk

deps = connect.go util.go tezosutil.go
deps2 = tezosutil.go 

createtezoskey: createtezoskey.go $(deps) 
	go build $^	

importtzsk2hsm: importtzsk2hsm.go $(deps)  
	go build $^	

gentzkeyfromhsmsk: gentzkeyfromhsmsk.go $(deps2) 
	go build $^	
