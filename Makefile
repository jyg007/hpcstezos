all: createtezoskey

deps = connect.go util.go

createtezoskey: createtezoskey.go $(deps)
	go build $^	
