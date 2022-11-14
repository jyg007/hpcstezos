all: createtezoskey importtzsk2hsm gentzkeyfromhsmsk tzderivekey

deps = connect.go util.go tezosutil.go
deps2 = tezosutil.go 

createtezoskey: createtezoskey.go $(deps) 
	go build $^	

importtzsk2hsm: importtzsk2hsm.go $(deps)  
	go build $^	

gentzkeyfromhsmsk: gentzkeyfromhsmsk.go $(deps2) 
	go build $^	

tzderivekey: tzderivekey.go $(deps)  
	go build $^	
