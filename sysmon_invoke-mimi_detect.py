# You can check mimikatz activity using sysmon event logs
# This tool display ...
# ProcessID
# Time
# AccountName
# Image (Parent process)
# ImageLoaded (Loaded Process by parent process)
#
#  This tool was tested on python 3
# Usage: python sysmon_mimi_detect your_ElasticserchServer_Address your_ElasticsearchServer_Port

import requests
import sys
import json
import pandas as pd

# DLL List
jsonstring = {
    "from": 0,
    "size":10000,
    "query": {
        "terms": {
            "event_data.ImageLoaded.keyword": [
                "C:\\Windows\\System32\\advapi32.dll",
                "C:\\Windows\\System32\\atl.dll",
                "C:\\Windows\\System32\\cfgmgr32.dll",
                "C:\\Windows\\System32\\clbcatq.dll",
                "C:\\Windows\\System32\\crypt32.dll",
                "C:\\Windows\\System32\\cryptbase.dll",
                "C:\\Windows\\System32\\cryptsp.dll",
                "C:\\Windows\\System32\\cscapi.dll",
                "C:\\Windows\\System32\\gdi32.dll",
                "C:\\Windows\\System32\\imm32.dll",
                "C:\\Windows\\System32\\linkinfo.dll",
                "C:\\Windows\\System32\\msasn1.dll",
                "C:\\Windows\\System32\\mscoree.dll",
                "C:\\Windows\\System32\\msvcrt.dll",
                "C:\\Windows\\System32\\ntmarta.dll",
                "C:\\Windows\\System32\\ntshrui.dll",
                "C:\\Windows\\System32\\ole32.dll",
                "C:\\Windows\\System32\\oleaut32.dll",
                "C:\\Windows\\System32\\profapi.dll",
                "C:\\Windows\\System32\\propsys.dll",
                "C:\\Windows\\System32\\psapi.dll",
                "C:\\Windows\\System32\\rpcrt4.dll",
                "C:\\Windows\\System32\\rsaenh.dll",
                "C:\\Windows\\System32\\sechost.dll",
                "C:\\Windows\\System32\\secur32.dll",
                "C:\\Windows\\System32\\shell32.dll",
                "C:\\Windows\\System32\\shlwapi.dll",
                "C:\\Windows\\System32\\srvcli.dll",
                "C:\\Windows\\System32\\sspicli.dll",
                "C:\\Windows\\System32\\user32.dll",
                "C:\\Windows\\System32\\userenv.dll",
                "C:\\Windows\\System32\\version.dll",
                "C:\\Windows\\System32\\ws2_32.dll",
                "C:\\Windows\\System32\\bcrypt.dll",
                "C:\\Windows\\System32\\bcryptprimitives.dll",
                "C:\\Windows\\System32\\cryptdll.dll",
                "C:\\Windows\\System32\\devobj.dll",
                "C:\\Windows\\System32\\dhcpcsvc.dll",
                "C:\\Windows\\System32\\dhcpcsvc6.dll",
                "C:\\Windows\\System32\\dnsapi.dll",
                "C:\\Windows\\System32\\gpapi.dll",
                "C:\\Windows\\System32\\hid.dll",
                "C:\\Windows\\System32\\logoncli.dll",
                "C:\\Windows\\System32\\mswsock.dll",
                "C:\\Windows\\System32\\NapiNSP.dll",
                "C:\\Windows\\System32\\ncrypt.dll",
                "C:\\Windows\\System32\\netapi32.dll",
                "C:\\Windows\\System32\\netutils.dll",
                "C:\\Windows\\System32\\nlaapi.dll",
                "C:\\Windows\\System32\\nsi.dll",
                "C:\\Windows\\System32\\rasadhlp.dll",
                "C:\\Windows\\System32\\rasapi32.dll",
                "C:\\Windows\\System32\\rasman.dll",
                "C:\\Windows\\System32\\rtutils.dll",
                "C:\\Windows\\System32\\samlib.dll",
                "C:\\Windows\\System32\\schannel.dll",
                "C:\\Windows\\System32\\setupapi.dll",
                "C:\\Windows\\System32\\vaultcli.dll",
                "C:\\Windows\\System32\\wbem\\fastprox.dll",
                "C:\\Windows\\System32\\wbem\\wbemprox.dll",
                "C:\\Windows\\System32\\wbem\\wbemsvc.dll",
                "C:\\Windows\\System32\\wbem\\wmiutils.dll",
                "C:\\Windows\\System32\\wbemcomn.dll",
                "C:\\Windows\\System32\\winhttp.dll",
                "C:\\Windows\\System32\\winnsi.dll",
                "C:\\Windows\\System32\\winrnr.dll",
                "C:\\Windows\\System32\\WinSCard.dll",
                "C:\\Windows\\System32\\wintrust.dll",
                "C:\\Windows\\System32\\Wldap32.dll"
            ]
        }
    }
}

# Counting number of detected DLL
minlistnum = len(jsonstring["query"]["terms"]["event_data.ImageLoaded.keyword"])

# Connect Elasticsearch Sever and send query
def sendrest(url):
    if len(sys.argv) != 2:
        sys.exit("Usage: %s eslasticsearch_address:Port" %sys.argv[0])

    # Please specify your Elasticsearch search path
    path = 'http://' + url[0] + '/winlogbeat-2017.08.26/_search?pretty=true'
    response = requests.get(path, data = json.dumps(jsonstring))
    parser(response)

# Parse and extract data
def parser(response):
    hitn = response.json()["hits"]["total"]
    eventlist = []

    for i in range(hitn):
        res_src = response.json()["hits"]["hits"][i]["_source"]
        eventdata = res_src["event_data"]["ProcessId"],res_src["@timestamp"],res_src["beat"]["name"],res_src["event_data"]["Image"],res_src["event_data"]["ImageLoaded"]
        taptolist = list(eventdata)
        eventlist.append(taptolist)
        #print(eventdata)
        if i == 9999:
            print("Elasticsearch doesn't return  more than 10,000 results.")
            sys.exit()
    pivot(eventlist)

# Create pivot table
def pivot(eventlist):
    # To avoid omission of long characters in columns
    pd.set_option("display.max_colwidth", 80)
    eventdf = pd.DataFrame(eventlist)
    eventdf.columns = ["ProcessID","Time","Account","Image","ImageLoaded"]
    imagept = eventdf.pivot_table(index="ImageLoaded",columns="ProcessID",values="Time",aggfunc=lambda x: len(x),fill_value = 0)
    global minlistnum
    if minlistnum != len(imagept):
        print("mimikatz activity is not detected.")
        sys.exit()

    for pid in imagept.columns:
        multic = 1
        for rowc in imagept.index:
            # ignore dll loaded count 0 (n * 0 = 0)
            multic = multic * imagept.ix[rowc, pid]
        if multic != 0:
            print("mimikatz activity detected!")
            print(pid)
            print(eventdf[eventdf.ProcessID == pid])
            print("")
    # Please remove comment out if you want to see pivot table
    #imagept.to_csv("imagept.csv")
    #print(imagept)

if __name__ == "__main__":
    sendrest(sys.argv[1:])
