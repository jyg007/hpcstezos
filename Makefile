all: createtezos 

deps = connect.go util.go

createtezos: createtezos.go $(deps)
	go build $^	
