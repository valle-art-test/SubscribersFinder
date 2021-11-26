import paramiko, maskpass, time, json, re, itertools


username = input('Username: ')
password = maskpass.advpass()
max_buffer = 65535


with open('commands.txt', 'r') as f: 
    commands = f.readlines()
# abriendo inventario de equipos
with open('inventory.json', 'r') as f:
    devices = json.load(f)
# abriendo archivo de usuarios fallidos conocidos
with open('KnownFailedUsers.txt', 'r') as f:
    KnownUsers = f.read().splitlines()
with open('BGPFailedUsers.txt', 'r') as f:
    KnownBGP = f.read().splitlines()



def clear_buffer(connection):
    if connection.recv_ready():
        return connection.recv(max_buffer)

def ParseSubscriber(lista):
    a = str(re.findall(r'[\$\][\w\.-]+@[\w\.-]+', lista))
    return a


def CleanStrToList(word):
    b = word.replace("[", "")
    b = b.replace("]", "")
    b = b.replace("'", "") 
    return b

def IpParser(string):
    a = str(re.findall(r'([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})', string))
    a = a.replace(", ", ".") 
    a = a.replace("(", "")
    a = a.replace(")", "")         
    return a


def ListDelta(list1, list2):
    list_difference = [item for item in set(list1) if item not in set(list2)]
    return list_difference


def ListCompare(list1, list2):
    c = set(list1).union(set(list2))
    d = set(list1).intersection(set(list2))
    return list(c - d)

def ListUnion(list1, list2):
    c = set(list1).union(set(list2))
    return list(c)

def ListIntersect(list1, list2):
    d = set(list1).intersection(set(list2))
    return list(d)

# Comenzamos el Loop para cada device, primero la conexion al equipo
for device in devices.keys(): 
    outputFileName = device + '_output.txt'
    connection = paramiko.SSHClient()
    connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connection.connect(devices[device]['ip'], username=username, password=password, allow_agent=False)
    new_connection = connection.invoke_shell()
    output = clear_buffer(new_connection)
    time.sleep(5)
    new_connection.send("environment no more\n")
    output = clear_buffer(new_connection)
    with open(outputFileName, 'wb') as f:
        for command in commands:
            new_connection.send(command)
            time.sleep(5)
            output = new_connection.recv(max_buffer)
            #print(output)
            f.write(output) 
    new_connection.close()
    
    # guardamos archivo con todos los logs
    with open(outputFileName, 'r') as f:
        ConfigAsList = f.read().splitlines()
        BufferLine=[]
        AuthFailures=[]
        ServFailures=[]
        BgpGroupFailures=[]
        BgpMD5Failures=[]
        FramedFailures=[]
        BGPClosed=[]
        AuthFailuresParsed=[]
        ServFailuresParsed=[]
        IpBgpGroupFailuresParsed=[]
        PolicyBgpGroupFailuresParsed=[]
        IpBgpMD5FailuresParsed=[]
        SidBgpMD5FailuresParsed=[]
        FramedFailuresParsed=[]
        BGPClosedParsed=[]
        for i in ConfigAsList:
            BufferLine.append(i)
            if re.search("Authentication failed", i) != None:
                AuthFailures.append(i)
            elif re.search("Service-id", i) != None:
                ServFailures.append(i)
            elif re.search("Invalid bgp peering policy", i) != None:
                BgpGroupFailures.append(i)
            elif re.search("MD5 authentication failure and possible reason is notConfigured", i) != None and not re.search("virtual router 1", i)!= None:
                BgpMD5Failures.append(i)  
            elif re.search("RADIUS attribute Framed-Routes error", i) != None:
                SubsFramedFailures.append(i)
            elif re.search("Connect", i) != None:
                BGPClosed.append(BufferLine[-2])




        ## Comienza el parceo
            # Authentication
        for i in AuthFailures:
            i = ParseSubscriber(i)            
            i = CleanStrToList(i)


            AuthFailuresParsed.append(i)    

        # Non Existed SID 
        for i in ServFailures:
            i = ParseSubscriber(i)            
            i = CleanStrToList(i)        
            ServFailuresParsed.append(i)    
    

        # IP BGP
        for i in BgpGroupFailures:
            i = IpParser(i)
            i = CleanStrToList(i)   
            IpBgpGroupFailuresParsed.append(i)
   

        # BGP-POLICY
        for i in BgpGroupFailures:
            i = str(re.findall(r'[\w\.-]+-[\w\.-]+-([0-9]{1,9})', i))
            i = CleanStrToList(i)  
            PolicyBgpGroupFailuresParsed.append(i)
 
    

        # MD5 Authentication
        for i in BgpMD5Failures:
            i = IpParser(i)
            i = CleanStrToList(i)
            IpBgpMD5FailuresParsed.append(i)
 

        for i in BgpMD5Failures:
            i = str(re.findall(r'[0-9]{1,9}[\w][\s]+TCP', i))
            i = i.replace(" TCP", "")
            i = CleanStrToList(i)
            SidBgpMD5FailuresParsed.append(i)

    

        for i in FramedFailures:
            i = ParseSubscriber(i)            
            i = CleanStrToList(i)       
            FramedFailuresParsed.append(i)



        # BGP Connect
        for i in BGPClosed:
            i = IpParser(i)
            i = CleanStrToList(i)
            #print(i)
            BGPClosedParsed.append(i)
 

    print("""


        """)

    print(f'RUNNING THE TEST ON DEVICE {device}')
    print("""


        """)

    print('###############################################################################################')
    


    bgptotalparsed = ListUnion(IpBgpMD5FailuresParsed, BGPClosedParsed)
    BGPproblems=ListIntersect(bgptotalparsed, KnownBGP)
    # Imprimir BGP MD5 Errors para BGP
    print('###############################################################################################')
    if BGPproblems==[]:
        print(f'{device} NO USERS WITH MD5 AUTHENTICATION ISSUES ARE REPORTED IN BGP AT {device}')
    else:
        setlist=set(BGPproblems)
        print(f'{device} USERS WITH MD5 AUTHENTICATION PROBLEM IN BGP IN {device} ACCORDING TO THE LIST ARE: ')
        for users in setlist:
            print(users)



    # Imprimir BGP POLICY GROUPS Errors
    print('###############################################################################################')
    if IpBgpGroupFailuresParsed==[]:
        print(f'{device} NO USERS WITH MIS CONFIGURATION ISSUES ARE REPORTED FOR BGP-POLICY-GROUP RADIUS ATT. IN {device}')
    else:
        setlist=set(IpBgpGroupFailuresParsed)
        print(f'{device} USERS WITH BGP-POLICY-GROUP ISSUES IN {device} ARE: ')
        for users in setlist:
            print(users)

        for ip, bgpgroup in zip(IpBgpGroupFailuresParsed, PolicyBgpGroupFailuresParsed):
            if not (ip=='' and bgpgroup==''):
                print('')
                print('')
                print('')
                print('THE FOLLOWING BGP POLICIES ARE INVALID')
                print(f'{ip}:       BGP-POLICY-GROUP-{bgpgroup}')





    # comparar con problemas de authenticacion conocidos
    aa = ListDelta(AuthFailuresParsed, KnownUsers)
    if aa == []:
        print(f'{device} USERS WITH AUTHENTICATION PROBLEMS ARE NOT REPORTED BASED ON THE KNOWN LIST IN {device}')
    else:
        print(f'{device} USERS IN {device} WITH AUTHENTICATION PROBLEMS BASED ON RICHARD'S LIST ARE AS FOLLOWS:')
        for users in aa:
            print(users)




    # Imprimir Framed-Routes Errors
    print('###############################################################################################')
    if FramedFailuresParsed==[]:
        print(f'{device} USERS WITH FRAMED-ROUTE RADIUS ATT PROBLEMS ARE NOT REPORTED. IN {device}')
    else:
        setlist=set(FramedFailuresParsed)
        print(f'{device} USERS WITH FRAMED-ROUTE RADIUS ATT ISSUE IN {device} ARE: ')
        for users in setlist:
            print(users)



    # Imprimir Service-id Errors
    print('###############################################################################################')
    if ServFailuresParsed == []:
        print(f'{device} USERS WITH SERVICE-ID ISSUES ARE NOT REPORTED IN {device}')
    else:
        setlist=set(ServFailuresParsed)
        print(f'{device} USERS WITH SERVICE-ID ISSUES IN {device} ARE: ')
        for users in setlist:
            print(users)



    print('###############################################################################################')


    print("""


        """)

    print(f'TEST EXECUTED SUCCESSFULLY ON DEVICE {device}')
    print("""


        """)

    print('###############################################################################################')

