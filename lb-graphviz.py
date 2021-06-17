#!/usr/bin/python3
# Copyright (c) 2021, Christopher Jay Cox <chriscox@endlessnow.com>
# 
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

#
# Queries a Kemp LoadMaster via API calls and returns a graphviz digraph.
# (does not try to understand everything)
# IMPORTANT: see section on /usr/local/etc/auths.conf

import json, requests, os, re, xmltodict, DNS


# /usr/local/etc/auths.conf format
#
# AUTH['kemp_ba'] = 'Basic encoded-string'
# AUTH['kemp_url'] = 'https://kemp-hostname'
#
# You want to protect it, and allow this script to read it.
#

#
# Read in auths, this is sort of generic (auths.conf might contain
#  many different auths)
#
kemp_ba_key = 'kemp_ba'
kemp_url_key = 'kemp_url'
basicauth = '/usr/local/etc/auths.conf'
AUTH={}
if (os.path.isfile(os.path.expanduser(basicauth))):
  with open(os.path.expanduser(basicauth),'r') as f:
    authdata = f.read()
  # sanitize 
  edata = "\n".join(re.findall(r'AUTH\[[^\[]+\]\s*=\s*.*', authdata))
  exec(edata)

auth = AUTH[kemp_ba_key]
headers = { 'Accept': 'application/json', 'Authorization': auth }
url = AUTH[kemp_url_key] + '/access/listvs'

xmlRaw = requests.get(url, headers = headers, verify = False)
xml=xmlRaw.text
myJson=xmltodict.parse(xml)

def findVS(name):
  for tempvs in myJson['Response']['Success']['Data']['VS']:
    try:
      if (tempvs['NickName'] == name):
        return(tempvs)
    except:
      continue
  return({})

def getRule(name):
  try:
    url = AUTH[kemp_url_key] + '/access/showrule?name=' + name
    ruleRaw = requests.get(url, headers = headers, verify = False)
    ruleXml = ruleRaw.text
    ruleJson = xmltodict.parse(ruleXml)
    return(ruleJson['Response']['Success']['Data'])
  except:
    return({})

def showRs(rsList, matchrules, redirectnodename=''):
  global graph
  dorules=True
  for rs in rsList:
    rs_enable=rs['Enable']
    if (redirectnodename == ''):
      rs_index=rs['RsIndex']
      rs_node_name='RS_' + rs_index
      rs_addr=rs['Addr']
      rs_port=rs['Port']
      try:
        rs_dnsname=rs['DnsName'] + ':' + rs_port + '\\n' + rs_addr + ':' + rs_port 
      except:
        rs_dnsname=rs_addr
    else:
      rs_index=rs['Index']
      rs_node_name='VS_' + rs_index
      rs_dnsname=rs['ErrorUrl']

    if (matchrules):
      rs_matchrules=matchrules
    else:
      rs_matchrules=[]
      try:
        if (isinstance(rs['MatchRules']['Name'],str)):
          rs_matchrules.append(rs['MatchRules']['Name'])
        else:
          rs_matchrules.extend(rs['MatchRules']['Name'])
      except:
        pass
    if (rs_enable == 'Y'):
      rule={}
      if (dorules):
        for rs_matchrule in rs_matchrules:
          rule=getRule(rs_matchrule)
          if (rule):
            rulepat=rule['MatchContentRule']['Pattern']
        if (matchrules):
          dorules=True
      print(rs_node_name,'[ label="' + rs_dnsname + '" ];')
      if (rule):
        graph.append('  ' + vs_node_name + ' -> ' + rs_node_name + ' [ label ="' + rulepat + '" ];')
      else:
        graph.append('  ' + vs_node_name + ' -> ' + rs_node_name + ';')

# Hardcoded preamble
print("""
digraph  loadbalancer {
   rankdir=LR;
   size="20,65";
   //splines=polylines;
   nodesep=0.25;
   ratio=fill;
   ranksep=0.15;
   //concentrate=true;
   /* node [shape=box style=filled fillcolor="grey93" fontsize=20.0]; */
   node [shape=box style=filled fillcolor="lightyellow" color="black" fontname="Helvetica" fontsize=20.0 margin=0.15 ];
""")

graph=[]
for vs in myJson['Response']['Success']['Data']['VS']:
  try:
    status=vs['Status']
  except:
    pass
  try:
    enable=vs['Enable']
  except:
    pass

  if (enable != 'Y'):
    continue
  if (status == 'Up' or status == 'Redirect'):
    try:
      nickname=vs['NickName']
    except:
      nickname='Unknown'
  
    try:
      # Non SubVS
      vsip=vs['VSAddress']
      try:
        vsdns=DNS.revlookup(vsip).upper() + "(" + vsip + ")"
      except:
        vsdns=vsip
      vs_index = vs['Index']
      vs_node_name='VS_' + vs_index
      vsport=vs['VSPort']
      print(vs_node_name,'[ label="' + nickname + '\\n' + vsdns + ':' + vsport + '" ];')
  
      try:
        if (isinstance(vs['Rs'], list)):
          rsList = vs['Rs']
        else:
          rsList = [ vs['Rs'] ]
      except:
        rsList = []

      try:
        subvsList = vs['SubVS']
        rsList = []
      except:
        subvsList = []

      for subvs in subvsList:
        subvs_name=subvs['Name']
        subvs_enable=subvs['Enable']
        vs_index=subvs['VSIndex']
        subvs_matchrules=[]
        try:
          if (isinstance(subvs['MatchRules']['Name'],str)):
            subvs_matchrules.append(subvs['MatchRules']['Name'])
          else:
            subvs_matchrules.extend(subvs['MatchRules']['Name'])
        except:
          pass
        if (subvs_enable == 'Y'):
          for subvs_matchrule in subvs_matchrules:
            nothing=1
          subvs_vs=findVS(subvs_name)
          redirectnodename=''
          if (subvs_vs):
            subvs_vs_index = subvs_vs['Index']
            subvs_vs_node_name='VS_' + subvs_vs_index
            subvs_vs_status = subvs_vs['Status']
            if (subvs_vs_status == 'Redirect'):
              subvs_vs_redirecturl=subvs_vs['ErrorUrl']
              redirectnodename=subvs_vs_node_name
              rsList = [ subvs_vs ]
            else:
              if (isinstance(subvs_vs['Rs'], list)):
                rsList = subvs_vs['Rs']
              else:
                rsList = [ subvs_vs['Rs'] ]
          showRs(rsList, subvs_matchrules, redirectnodename)
      if (not subvsList):
        showRs(rsList, {})
    except:
      pass

for line in graph:
  print(line)

print('}')
