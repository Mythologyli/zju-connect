package parser

import (
	"fmt"
	"github.com/mythologyli/zju-connect/core/config"
	"log"
	"math"
	"net"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
)

var domainRegExp *regexp.Regexp

func StringArrToIntArr(strArr []string) [4]int {
	var intArr [4]int

	for index, str := range strArr {
		intArr[index], _ = strconv.Atoi(str)
	}

	return intArr
}

func getMaskByIpRange(fromIp string, toIp string) (ones int, bits int) {
	fromIpSplit := StringArrToIntArr(strings.Split(fromIp, "."))
	toIpSplit := StringArrToIntArr(strings.Split(toIp, "."))

	fromIpSplit[3] = int(math.Max(float64(fromIpSplit[3]-1), 0))
	toIpSplit[3] = int(math.Min(float64(toIpSplit[3]+1), 255))

	var mask [4]byte
	for i := 3; i >= 0; i-- {
		mask[i] = uint8(255 - toIpSplit[i] + fromIpSplit[i])
	}

	return net.IPv4Mask(mask[0], mask[1], mask[2], mask[3]).Size()
}

// from https://github.com/dromara/hutool/blob/fc091b01a23271e02f3174c45942105048155c90/hutool-core/src/main/java/cn/hutool/core/net/Ipv4Util.java#L114
func getIPsInRange(from, to string) *[]string {
	ipf := StringArrToIntArr(strings.Split(from, "."))
	ipt := StringArrToIntArr(strings.Split(to, "."))

	ips := make([]string, 4096)

	equ := func(condition bool, yes int, no int) int {
		if condition {
			return yes
		} else {
			return no
		}
	}

	var a, b, c int

	for a = ipf[0]; a <= ipt[0]; a++ {
		for b = equ(a == ipf[0], ipf[1], 0); b <= equ(a == ipt[0], ipt[1], 255); b++ {
			for c = equ(b == ipf[1], ipf[2], 0); c <= equ(b == ipt[1], ipt[2], 255); c++ {
				for d := equ(c == ipf[2], ipf[3], 0); d <= equ(c == ipt[2], ipt[3], 255); d++ {
					ips = append(ips, strconv.Itoa(a)+"."+strconv.Itoa(b)+"."+strconv.Itoa(c)+"."+strconv.Itoa(d))
				}
			}
		}
	}

	return &ips
}

func countByIpRange(from string, to string) int {
	count := 1
	ipf := StringArrToIntArr(strings.Split(from, "."))
	ipt := StringArrToIntArr(strings.Split(to, "."))

	for i := 3; i >= 0; i-- {
		count += (ipt[i] - ipf[i]) * int(math.Pow(256, float64(3-i)))
	}

	return count
}

func processSingleIpRule(rule, port string, debug bool, waitChan *chan int) {
	appendRule := func(value *string, isIPV4RangeRule bool, isCIDR bool) {
		minValue := port
		maxValue := port

		if strings.Contains(port, "~") {
			minValue = strings.Split(port, "~")[0]
			maxValue = strings.Split(port, "~")[1]
		}

		minValueInt, err := strconv.Atoi(minValue)
		if err != nil {
			log.Printf("Cannot parse port value from string")
			return
		}

		maxValueInt, err := strconv.Atoi(maxValue)
		if err != nil {
			log.Printf("Cannot parse port value from string")
			return
		}

		if debug {
			log.Printf("Appending Domain rule for: %s%v isIpv4RangeRule: %v isCIDR: %v", *value, []int{minValueInt, maxValueInt}, isIPV4RangeRule, isCIDR)
		}

		if isIPV4RangeRule {
			config.AppendSingleIpv4RangeRule(*value, []int{minValueInt, maxValueInt}, isCIDR, debug)
		} else {
			config.AppendSingleDomainRule(*value, []int{minValueInt, maxValueInt}, debug)
		}
	}

	if strings.Contains(rule, "~") { // ip range 1.1.1.7~1.1.7.9
		from := strings.Split(rule, "~")[0]
		to := strings.Split(rule, "~")[1]
		size := countByIpRange(from, to)

		mask, k := getMaskByIpRange(from, to)

		if debug {
			log.Printf("Handling rule for: %s-%s mask: %v", from, to, mask)
		}

		// mask == 0 -> cannot cover to cidr
		if mask != 0 && mask <= 28 {
			if debug {
				log.Printf("using Cidr %s-%s mask: %v %v", from, to, mask, k)
			}

			cidr := fmt.Sprintf("%s/%v", from, mask)

			appendRule(&cidr, true, true)
		} else {
			if size > 4096 {
				log.Printf("Super large rule detected for: %s-%s mask: %v", from, to, mask)

				appendRule(&rule, true, false)
			} else {
				if size > 1024 {
					log.Printf("Large rule detected for: %s-%s mask: %v", from, to, mask)
				}

				for _, domain := range *getIPsInRange(from, to) {
					appendRule(&domain, false, false)
				}
			}
		}
	} else { // http://domain.example.com/path/to&something=good#extra
		appendRule(&rule, false, false)

		if domainRegExp == nil {
			domainRegExp, _ = regexp.Compile("(?:\\w+\\.)+\\w+")
		}

		pureDomain := domainRegExp.FindString(rule)

		appendRule(&pureDomain, false, false) //TODO::FIXME:: remove this when using Http(s) proxy
	}

	*waitChan <- 1
}

func processDnsData(dnsData string, debug bool) {
	for _, ent := range strings.Split(dnsData, ";") {
		dnsEntry := strings.Split(ent, ":")

		if len(dnsEntry) >= 3 {
			RcID := dnsEntry[0]
			domain := dnsEntry[1]
			ip := dnsEntry[2]

			if debug {
				log.Printf("[%s] %s %s", RcID, domain, ip)
			}

			if domain != "" && ip != "" {
				config.AppendSingleDnsRule(domain, ip, debug)
			}
		}
	}
}

func processRcsData(rcsData config.Resource, debug bool, waitChan *chan int, cpuNumber *int) {
	RcsLen := len(rcsData.Rcs.Rc)
	for RcsIndex, ent := range rcsData.Rcs.Rc {
		if debug {
			log.Printf("[%s] %s %s", ent.Name, ent.Host, ent.Port)
		}

		if ent.Host == "" || ent.Port == "" {
			log.Printf("Found null entry when processing RcsData: [%s] %s %s", ent.Name, ent.Host, ent.Port)
			continue
		}

		domains := strings.Split(ent.Host, ";")
		ports := strings.Split(ent.Port, ";")

		if len(domains) >= 1 && len(ports) >= 1 {
			for index, domain := range domains {
				portRange := ports[index]

				if *cpuNumber > 0 {
					*cpuNumber--
				} else {
					<-*waitChan
				}
				processSingleIpRule(domain, portRange, debug, waitChan)
			}
		}

		log.Printf("Progress: %v/100 (ResourceList.Rcs)", int(float32(RcsIndex)/float32(RcsLen)*100))
	}
}

func ParseResourceLists(host, twfID string, debug bool) {
	ResourceList := config.Resource{}
	res, ok := ParseXml(&ResourceList, host, config.PathRlist, twfID)

	cpuNumber := runtime.NumCPU()
	waitChan := make(chan int, cpuNumber)

	if !ok || ResourceList.Rcs.Rc == nil || len(ResourceList.Rcs.Rc) <= 0 || ResourceList.Dns.Data == "" {
		if res != "" {
			log.Printf("try parsing by regexp")

			escapeReplacementMap := map[string]string{
				"&nbsp;": string(rune(160)),
				"&amp;":  "&",
				"&quot;": "\"",
				"&lt;":   "<",
				"&gt;":   ">",
			}

			for from, to := range escapeReplacementMap {
				res = strings.ReplaceAll(res, from, to)
			}

			resUrlDecodedValue, err := url.QueryUnescape(res)
			if err != nil {
				log.Printf("Cannot do UrlDecode")
				return
			}

			ResourceListRegexp := regexp2.MustCompile("(?<=\" host=\").*?(?=\" enable_disguise=)", 0)
			ResourceListMatches, _ := ResourceListRegexp.FindStringMatch(resUrlDecodedValue)
			for ; ResourceListMatches != nil; ResourceListMatches, _ = ResourceListRegexp.FindNextMatch(ResourceListMatches) {

				if debug {
					log.Printf("ResourceListMatch -> " + ResourceListMatches.String() + "\n")
				}

				ResourceListData := ResourceListMatches.String()

				ResourceListDataHost := strings.Split(ResourceListData, "\" port=\"")[0]
				ResourceListDataPort := strings.Split(ResourceListData, "\" port=\"")[1]

				entry := config.RcData{Host: ResourceListDataHost, Port: ResourceListDataPort}
				ResourceList.Rcs.Rc = append(ResourceList.Rcs.Rc, entry)
			}

			processRcsData(ResourceList, debug, &waitChan, &cpuNumber)

			log.Printf("Parsed %v domain rules", config.GetDomainRuleLen())
			log.Printf("Parsed %v IPv4 rules", config.GetIpv4RuleLen())

			DnsDataRegexp := regexp2.MustCompile("(?<=<Dns dnsserver=\"\" data=\")[0-9A-Za-z:;.-]*?(?=\")", 0)
			DnsDataRegexpMatches, _ := DnsDataRegexp.FindStringMatch(resUrlDecodedValue)

			processDnsData(DnsDataRegexpMatches.String(), debug)

			log.Printf("Parsed %v DNS rules", config.GetDnsRuleLen())
		}
	} else {
		log.Printf("try parsing by goXml")

		processRcsData(ResourceList, debug, &waitChan, &cpuNumber)

		log.Printf("Parsed %v domain rules", config.GetDomainRuleLen())
		log.Printf("Parsed %v IPv4 rules", config.GetIpv4RuleLen())

		processDnsData(ResourceList.Dns.Data, debug)

		log.Printf("Parsed %v DNS rules", config.GetDnsRuleLen())
	}
}

func ParseConfLists(host, twfID string, debug bool) {
	conf := config.Conf{}
	_, _ = ParseXml(&conf, host, config.PathConf, twfID)
}
