# This project is a command line tool that I can use at work to check
# Whois records, DNS records, Port scanner, and IP Geolocate.
import whois
import dns.resolver
import geocoder
import nmap

def who_is():
    print('Input Domain')
    domain_query = input()

    domain = whois.whois(domain_query)
    print(domain)

def dns_records():
    print('Input Domain')
    domain = input()
    # This finds the 'AAAA' record and displays it as a ip address
    # Attempts to find a AAAA record. But if the record does not exist it prints that text.
    print('AAAA Records')
    try:
        aaaa_record = dns.resolver.resolve(domain, 'AAAA')
        for rdata in aaaa_record:
            print(rdata.address)
    except Exception as e:
        print(e)
    # I want a blank line in the results.
    print('')

    # This finds the 'A' record and displays it as a ip address
    a_record = dns.resolver.resolve(domain, 'A')
    print('A Records')
    for rdata in a_record:
        print(rdata.address)

    print('')

    # This finds the 'TXT' record and displays it as text
    txt_record = dns.resolver.resolve(domain, 'TXT')
    print('TXT Records')
    for rdata in txt_record:
        print(rdata.to_text())

    print('')

    # This finds the 'MX' record and displays it as text
    mx_record = dns.resolver.resolve(domain, 'MX')
    print('MX Records')
    for rdata in mx_record:
        print(rdata.to_text())

    print('')
    # This finds the 'CNAME' record and displays it as text
    print('CNAME Records')
    try:
        cname_record = dns.resolver.resolve(domain, 'CNAME')
        for rdata in cname_record:
            print(rdata.to_text())
    except Exception as e:
            print(e)

    print('')

    # This finds the 'NS' record and displays it as text
    ns_record = dns.resolver.resolve(domain, 'NS')
    print('NS Records')
    for rdata in ns_record:
        print(rdata.to_text())

def ip_geolocate():
    print('Type the IP you want to know the location of.')
    ip_address = input()
    g = geocoder.ip(ip_address)
    g.latlng
    g.city
    g.state
    g.country
    print('IP Location is: ')
    print(g.city + ', ' + g.state)
    print(g.country)
    print(g.latlng)

def port_scan():
        while True:
            print('What ports to scan?')
            print('1. First 1000.')
            print('2. Common Ports')
            print('3. Entire Range 1-65535')
            print('4. List Common Ports')

            port_input = input()

            if port_input == '1':
                port_search = '1-1000'
                break
            elif port_input == '2':
                port_search = '20,21,22,23,25,53,80,110,123,143,993,161,443,3389'
                break
            elif port_input == '3':
                port_search = '1-65535 This may take some time'
                break
            elif port_input == '4':
                print('FTP 20/21, SSH 22, TELNET 23, SMTP 25, DNS 53, HTTP 80, POP3 110, NTP 123, IMAP 143/993, SNMP 161, HTTPS 443, RDP 3389')
            else:
                print('Invalid Choice')


        print('Input domain or IP address.')
        port_query = input()
        n = nmap.PortScanner()
        n.scan(port_query, port_search)

        #This breaks down the nested dict into what I need and iterates so that no matter how many ports are open they are shown.
        for host in n.all_hosts():
            for protocol in n[host].all_protocols():
                ports = n[host][protocol].keys()
                for port in sorted(ports):
                    state = n[host][protocol][port]['state']
                    service = n[host][protocol][port]['name']
                    port_string = str(port)
                    print('Port ' + port_string + '   Service: ' + service + '   State: '+ state)

while True:
    print('Select from the options below.')
    print('1. Who is Query')
    print('2. DNS Record List')
    print('3. IP Geolocate')
    print('4. Port Scan')
    print('5. End Program')
    user_choice = input()
    if user_choice == '1':
        who_is()
    elif user_choice == '2':
        dns_records()
    elif user_choice == '3':
        ip_geolocate()
    elif user_choice == '4':
        port_scan()
    elif user_choice == '5':
        break
    else:
        print('Invalid Option.')