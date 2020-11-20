# restclient

Package `restclient` implements a `http.Client` and make http on behalf of `http.Client` to their respective Server.

###Install
With a correctly configured Go toolchain:

        go get github.com/codagelabs/restclient


###Examples


        func main() {
        		
        		type Resp struct {
        		}
        
        		var url = ""
        
        		resp := Resp{}
        		var status int
        
        		err := request.NewRestClient(&http.Client{}).NewRequest().GetResponseAs(&resp).GetResponseStatusCodeAs(&status).GET(url)
        		if err != nil {
        			fmt.Println(err)
        		}
        
        		fmt.Println(resp)
        		fmt.Println(status)
        
        	}