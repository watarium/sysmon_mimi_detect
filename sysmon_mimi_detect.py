import requests
import sys
import json
import pandas as pd
import pprint

jsonstring = {
    "from": 0,
    "size":10000,
    "query": {
        "terms": {
            "event_data.ImageLoaded.keyword": [
                "C:\\Windows\\System32\\samlib.dll",
                "C:\\Windows\\System32\\crypt32.dll",
                "C:\\Windows\\System32\\sspicli.dll",
                "C:\\Windows\\System32\\user32.dll",
                "C:\\Windows\\System32\\imm32.dll",
                "C:\\Windows\\System32\\msasn1.dll",
                "C:\\Windows\\System32\\msvcrt.dll",
                "C:\\Windows\\System32\\cryptdll.dll",
                "C:\\Windows\\System32\\vaultcli.dll",
                "C:\\Windows\\System32\\gdi32.dll",
                "C:\\Windows\\System32\\sechost.dll",
                "C:\\Windows\\System32\\rpcrt4.dll",
                "C:\\Windows\\System32\\shell32.dll",
                "C:\\Windows\\System32\\kernel32.dll",
                "C:\\Windows\\System32\\rsaenh.dll",
                "C:\\Windows\\System32\\advapi32.dll",
                "C:\\Windows\\System32\\secur32.dll",
                "C:\\Windows\\System32\\KernelBase.dll",
                "C:\\Windows\\System32\\ntdll.dll",
                "C:\\Windows\\System32\\shlwapi.dll"
            ]
        }
    }
}


def sendrest(url):
    if len(sys.argv) != 2:
        sys.exit("Usage: %s eslasticsearch_address:Port" %sys.argv[0])

    path = 'http://' + url[0] + '/winlogbeat-*/_search?pretty=true'
    response = requests.get(path, data = json.dumps(jsonstring))
    #print(json.dumps(jsonstring))
    #pprint.pprint(response.json())
    parser(response)

def parser(response):
    hitn = response.json()["hits"]["total"]
    eventlist = []

    for i in range(hitn):
        res_src = response.json()["hits"]["hits"][i]["_source"]
        eventdata = res_src["event_data"]["ProcessId"],res_src["@timestamp"],res_src["beat"]["name"],res_src["event_data"]["Image"],res_src["event_data"]["ImageLoaded"]
        taptolist = list(eventdata)
        eventlist.append(taptolist)
        #print(eventdata)
    pivot(eventlist)

def pivot(eventlist):
    eventdf = pd.DataFrame(eventlist)
    eventdf.columns = ["ProcessID","Time","Client","Image","ImageLoaded"]
    imagept = eventdf.pivot_table(index="ImageLoaded",columns="ProcessID",values="Time",aggfunc=lambda x: len(x),fill_value = 0)

    for pid in imagept.columns:
        multic = 1
        for rowc in imagept.index:
            multic = multic * imagept.ix[rowc, pid]
        if multic != 0:
            print("mimikatz activity detected!")
            print(pid)
            print(eventdf[eventdf.ProcessID == pid])
            print("")
    #imagept.to_csv("imagept.csv")
    #print(imagept)


if __name__ == "__main__":
    sendrest(sys.argv[1:])
