package main

import (
	"fmt"
	"github.com/codagelabs/restclient/request"
	"net/http"
)

type DownstreamService interface {
	ExecRequest() (respModel, error)
}

type downstreamService struct {
	restClient request.RestClient
}

func NewDownstreamService(restClient request.RestClient) DownstreamService {
	return downstreamService{restClient: restClient}
}

type respModel struct {
	ErrorMessage string `json:"errorMessage"`
	Status       string `json:"status"`
}

func (ds downstreamService) ExecRequest() (respModel, error) {
	resp := respModel{}
	err := ds.restClient.NewRequest().GetResponseAs(&resp).GET("https://maps.googleapis.com/maps/api/timezone/json")
	if err != nil {
		return respModel{}, err
	}
	return resp, nil

}
func main() {

	client := http.Client{}
	restClient := request.NewRestClient(&client)
	downStreamService := NewDownstreamService(restClient)
	execRequest, err := downStreamService.ExecRequest()
	if err != nil {
		fmt.Printf("%v", err)
	}
	fmt.Printf("%+v", execRequest)

}
