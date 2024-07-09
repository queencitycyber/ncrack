// Refs: https://harrisonm.com/blog/nsec-walking


package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	blue   = "\033[1;34m"
	cyan   = "\033[1;36m"
	green  = "\033[1;32m"
	grey   = "\033[1;90m"
	pink   = "\033[1;95m"
	purple = "\033[0;35m"
	red    = "\033[1;31m"
	yellow = "\033[1;33m"
	reset  = "\033[0m"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		printHelp()
		return
	}

	if len(os.Args) == 2 {
		nsecCrawl(os.Args[1])
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			nsecCrawl(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "error reading input:", err)
		}
	}
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("    Single:")
	fmt.Println("        ./nwalk <domain>")
	fmt.Println("    List:")
	fmt.Println("        cat domains.txt | ./nwalk")
	fmt.Println("    Fast List:")
	fmt.Println("        parallel -a domains.txt -j 10 ./nwalk")
}

func nsecCrawl(domain string) {
	domain = cleanDomain(domain)
	fmt.Printf("%sNameservers for %s%s%s\n", pink, cyan, domain, reset)

	nameservers := getNameservers(domain)
	if len(nameservers) == 0 {
		fmt.Printf("    %sNone for %s%s%s\n", grey, cyan, domain, reset)
		return
	}

	fmt.Printf("    %s%d found for %s%s%s\n", blue, len(nameservers), cyan, domain, reset)

	nsIPList := getNameserverIPs(nameservers, domain)
	if len(nsIPList) == 0 {
		fmt.Printf("    %sNo IPs for %s%s%s\n", grey, cyan, domain, reset)
		return
	}

	fmt.Printf("    %s%d IPs for %s%s%s\n", blue, len(nsIPList), cyan, domain, reset)

	currentDomain := domain
	count := 0
	errorCount := 0
	ns := nsIPList[rand.Intn(len(nsIPList))]

	for {
		if len(nameservers) == 0 || len(nsIPList) == 0 {
			fmt.Printf("%sNo nameservers left for %s%s%s\n", grey, cyan, domain, reset)
			return
		}

		nsDomain, nsIP := ns[0], ns[1]
		nsec := getNSECRecord(nsIP, currentDomain)

		if nsec == "" {
			errorCount++
			if errorCount == 3 {
				fmt.Printf("        %sFailed with %s%s %s(%s)%s for %s%s%s\n", red, purple, nsDomain, grey, nsIP, red, cyan, domain, reset)
				nsIPList = removeIP(nsIPList, nsIP)
				if len(nsIPList) == 0 {
					fmt.Printf("%sNo IPs left for %s%s%s\n", grey, cyan, domain, reset)
					return
				}
				ns = nsIPList[rand.Intn(len(nsIPList))]
				errorCount = 0
			}
			continue
		}

		errorCount = 0

		if nsec == domain || nsec == currentDomain {
			break
		}

		if strings.HasPrefix(nsec, "\000.") {
			break
		}

		count++
		writeToFile(fmt.Sprintf("nwalk_out/nsec-%s.txt", domain), nsec)
		fmt.Printf("        %sNSEC for %s%s%s from %s%s %s(%s)%s: %s%s%s\n", green, cyan, domain, green, purple, nsDomain, grey, nsIP, green, yellow, nsec, reset)
		currentDomain = nsec
	}

	if count == 0 {
		fmt.Printf("%sNo NSEC records for %s%s%s from %s%s%s\n", red, cyan, domain, red, purple, ns, reset)
	} else {
		fmt.Printf("%s%d NSEC records for %s%s%s\n", green, count, cyan, domain, reset)
	}
}

func cleanDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}

func getNameservers(domain string) []string {
	out, err := exec.Command("dig", "+short", "+retry=3", "+time=10", domain, "NS").Output()
	if err != nil {
		return nil
	}
	nameservers := strings.Fields(string(out))
	for i, ns := range nameservers {
		nameservers[i] = strings.TrimSuffix(ns, ".")
	}
	return nameservers
}

func getNameserverIPs(nameservers []string, domain string) [][2]string {
	var nsIPList [][2]string
	for _, ns := range nameservers {
		fmt.Printf("        %sIPs for %s%s%s\n", pink, purple, ns, reset)
		out, err := exec.Command("dig", "+short", "+retry=5", "+time=10", ns, "A", ns, "AAAA").Output()
		if err != nil {
			continue
		}
		nsIPs := strings.Fields(string(out))
		if len(nsIPs) == 0 {
			fmt.Printf("            %sNone for %s%s%s\n", grey, purple, ns, grey)
			continue
		}
		fmt.Printf("            %s%d IPs for %s%s%s\n", blue, len(nsIPs), purple, ns, blue)
		for _, ip := range nsIPs {
			nsIPList = append(nsIPList, [2]string{ns, ip})
		}
	}
	return nsIPList
}

func getNSECRecord(nsIP, currentDomain string) string {
	out, err := exec.Command("dig", "+short", "+retry=5", "+time=10", "@"+nsIP, currentDomain, "NSEC").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, ";;") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			return strings.TrimSuffix(fields[0], ".")
		}
	}
	return ""
}

func writeToFile(filename, content string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("error opening file:", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(content + "\n"); err != nil {
		fmt.Println("error writing to file:", err)
	}
}

func removeIP(nsIPList [][2]string, ip string) [][2]string {
	for i, nsIP := range nsIPList {
		if nsIP[1] == ip {
			return append(nsIPList[:i], nsIPList[i+1:]...)
		}
	}
	return nsIPList
}
