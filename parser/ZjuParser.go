package parser

import "EasierConnect/core/config"

func ParseZjuDnsRules(debug bool) {

}

func ParseZjuForceProxyRules(debug bool) {
	config.AppendSingleZjuForceProxyRule("zju.edu.cn", debug)
}
