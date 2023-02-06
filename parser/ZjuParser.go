package parser

import "github.com/mythologyli/zju-connect/core/config"

func ParseZjuDnsRules(debug bool) {

}

func ParseZjuIpv4Rules(debug bool) {
	config.AppendSingleIpv4RangeRule("10.0.0.0/8", []int{1, 65535}, true, debug)
}

func ParseZjuForceProxyRules(debug bool) {
	config.AppendSingleZjuForceProxyRule("zju.edu.cn", debug)
}
