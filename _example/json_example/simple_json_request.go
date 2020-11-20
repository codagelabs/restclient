package main

import (
	"fmt"
	"github.com/codagelabs/restclient/request"
	"net/http"
)

type respModel struct {
	ErrorMessage string `json:"errorMessage"`
	Status       string `json:"status"`
}

func execRequest(restClient request.RestClient) (*respModel, error) {
	resp := respModel{}
	err := restClient.NewRequest().GetResponseAs(&resp).GET("https://maps.googleapis.com/maps/api/timezone/json")
	if err != nil {
		return nil, err
	}
	return &resp, nil

}
func main() {

	client := http.Client{}
	restClient := request.NewRestClient(&client)
	resp, err := execRequest(restClient)
	if err != nil {
		fmt.Printf("%v", err)
	}
	fmt.Printf("%+v", resp)

}
