import subprocess
import psutil
import pefile
def main():
# ============== EXECUTABLE PATH ====================
	def _get_exec_(pid):
		p = psutil.Process(pid)
		return(p.exe())
# ============== PROCESS NAME =======================
	def _get_process_name_(pid):
		a = psutil.Process(pid)
		return(a.name())
# ============== PROCESS USER NAME API ==================
	def _get_user_name_(pid):
		n = psutil.Process(pid)
		return(n.username())
# ============== CHECK WHETHER PROCESS OWNER IS SYSTEM ====================
	def _checks_system_process_(pid):
		sysprocess = False
		command = "wmic process where processid=%d call getowner|findstr Domain" % pid
		wmicdomain = subprocess.check_output(command, shell=True)
		wmicstr = wmicdomain.decode("utf-8")
		wmist = wmicstr.split()
	#	print(wmist)
		for i in range(2):
			wmist.pop(0)
	#		print(wmist)
			if len(wmist) > 1:
				a = wmist[1].replace('";', "")
				if a == "AUTHORITY":
					sysprocess = True
					return(sysprocess)
			else:
				pass
		
			
		
# ============== WMIC GET EXECUTABLE PATH ===========
	def _wmi_execpath_(pid):
#		command = 'wmic process where processid=%d get executablepath' %pid
#		wmiclist = subprocess.check_output(command, shell=True)
#		wmicstr = wmiclist.decode("utf-8")
#		wmist = wmicstr.split()
#		try:
#			return(wmist[1])
#		except IndexError:
#			print("SUMTING WONG WITH WMIC GET EXEC PATH !!!")
		
		command = 'wmic process where processid=%d get executablepath' %pid
		wmiclist = subprocess.check_output(command, shell=True)
		wmicstr = wmiclist.decode("utf-8")
		wmist = wmicstr.split()
		wmist.pop(0)
		for i in range(len(wmist)):
#			print(wmist)
			if len(wmist) == i+1 and len(wmist) > 1:
				print("wmist content")
			#	print(wmist)
				a = ', '.join(wmist[0::i])
				b = a.replace(",", "")
				return(b)
			else:
				b = ''.join(wmist)
			#	print(b)
				return(b)
# ============== CHECK SIGNATURE OF FILE ============
	def _signature_(execpath):
		#exe_path = execpath.replace("\\", "\\\\")
		try:
			pe = pefile.PE(execpath)
			return(pe.VS_FIXEDFILEINFO)
		except FileNotFoundError:
			pass
		
# ============= RULE 01 - CONNECTION BY NOT PORT 80 - 443 ==========
	def _rule_01_(remoteport):
		param = "80 - 443"
		if remoteport != 80 and remoteport != 443:
			alert = "Rule 1 !!! \n SUSPICIOUS CONNECTION NOT IN %s \n PROCESS: %s \n PID: %d \n CONNECTED_TO: %s \n WITH_PORT: %d \n EXEC_PATH: %s" %(param, process_name, pid, remoteip, remoteport, executable_path)
			return(alert)
# ============= RULE 02 - CONNECTION ON PORT 80 - 443 BUT PROCESS NAME NOT IN CHROME.EXE - FIREFOX.EXE - BROWSER.EXE ========
	def _rule_02_(process_name, remoteport):
		if remoteport == 443 or remoteport == 80:
			param = "chrome.exe - firefox.exe - iexplore.exe - browser.exe"
			if process_name != "chrome.exe" and process_name != "firefox.exe" and process_name != "iexplore.exe" and process_name != "browser.exe":
				alert = "Rule 2 !!! \n SUSPICIOUS CONNECTION NOT IN %s \n PROCESS: %s \n PID: %d \n CONNECTED_TO: %s \n WITH_PORT: %d \n EXEC_PATH: %s" %(param, process_name, pid, remoteip, remoteport, executable_path)
				return(alert)
# ============= Rule 03 - CONNECTION ON PORT POP/S - IMAP/S BUT PROCESS NAME NOT IN OUTLOOK.EXE - THUNDERBIRD.EXE ===========
	def _rule_03_(process_name, remoteport):
		if remoteport == 25 or remoteport == 587 or remoteport == 465 or remoteport == 143 or remoteport == 993 or remoteport == 110 or remoteport ==995:
			param = "outlook.exe - thunderbird.exe - OUTLOOK.exe"
			if process_name != "outlook.exe" and process_name != "thunderbird.exe" and process_name != "OUTLOOK.exe":
				alert = "Rule 3 !!! \n SUSPICIOUS MAIL CLIENT NOT IN %s \n PROCESS: %s \n PID: %d \n CONNECTED_TO: %s \n WITH_PORT: %d \n EXEC_PATH: %s" %(param, process_name, pid, remoteip, remoteport, executable_path)
				return(alert)			
# ============= Rule 04 - CONNECTION ESTABLISHED BY SYSTEM USER ===========================================================================
	def _rule_04_(pid):
		proces_owner = _checks_system_process_(pid)
		#	print(proces_owner)
		if proces_owner == True:
			alert = "Rule 4 !!! \n Connection establisted by SYSTEM USER \n PROCESS: %s \n PID: %d \n CONNECTED_TO: %s \n WITH_PORT: %d \n EXEC_PATH: %s" %(process_name, pid, remoteip, remoteport, executable_path)
			return(alert)
# ============= Rule 05 - SYSTEM PROCESSES WERE NOT SIGNED ===================================================================
	def _rule_05_(pid):
		try:
			system_process = _checks_system_process_(pid)
		except subprocess.CalledProcessError:
			pass
		try:
			if system_process == True:
				exec_path = _wmi_execpath_(pid)
				signature = _signature_(exec_path)
				#	print(signature)
				alert = "Rule 5 !!! \n SUSPICIOUS SYSTEM USER PROCESS %s WAS NOT SIGNED \n LOCATED AT %s \n WITH PROCESS ID %d " %(process_name, exec_path, pid)
				return(alert)
		except UnboundLocalError:
			print(system_process)
# ============= Rule 06 - PROCESSES NAMED LIKE SYSTEM PROCESS BUT WAS NOT SIGNED =============================================
	def _rule_06_(process_name, pid):
	#	print("Rule 6")
		param = "smss.exe - csrss.exe - wininit.exe - winlogon.exe - services.exe - lsass.exe - lsm.exe - svchost.exe - conhost.exe - spoolsv.exe - SearchIndexer.exe - LMS.exe"
		
		if process_name == "smss.exe" or process_name == "csrss.exe" or process_name == "wininit.exe" or process_name == "winlogon.exe" or process_name == "services.exe" or process_name == "lsass.exe" or process_name == "lsm.exe" or process_name == "svchost.exe" or process_name == "spoolsv.exe" or process_name == "SearchIndexer.exe" or process_name == "LMS.exe":
			exec_path = _wmi_execpath_(pid)
	#		print("Matched")
	#		print(process_name)
			try:
				signature = _signature_(exec_path)
			#	print(signature)
			except AttributeError:
				alert = "Rule 6 !!! \n SUSPICIOUS PROCESSES NAMED %s WAS NOT SIGNED \n LOCATED AT %s \n WITH PROCESS ID %d " %(process_name, exec_path, pid)
				return(alert)
# ============== NETSTAT ============================
	netstat = []
	netstatlist = subprocess.check_output("netstat -no", shell=True)
	netstatstr = netstatlist.decode("utf-8")
	netst = netstatstr.split()

	for i in range(len(netst)):
		if netst[i] == "TCP":
			try:
				protocol = "TCP"
				localip, localport = netst[i + 1].split(':')
				remoteip, remoteport = netst[i + 2].split(':')
				status = netst[i + 3]
				pid = int(netst[i + 4])
				executable_path	= _get_exec_(pid)
				process_name = _get_process_name_(pid)
			#	print(remoteport)
				rule1 = _rule_01_(int(remoteport))
				rule2 = _rule_02_(process_name, int(remoteport))
				rule3 = _rule_03_(process_name, int(remoteport))
				rule4 = _rule_04_(pid)

				if rule1 != None:
					print(rule1)
					print(".-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.")
				if rule2 != None:
					print(rule2)
					print(".-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.")
				if rule3 != None:
					print(rule3)
					print(".-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.")
				if rule4 != None:
					print(rule4)
					print(".-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.")
			except psutil.AccessDenied:
				pass
			#	print("Something went wrong with ProcessId")
			#	print(pid)
# ==================
	command = 'wmic process get caption, processid'
	wmiclist = subprocess.check_output(command, shell=True)
	wmicstr = wmiclist.decode("utf-8")
	wmist = wmicstr.split()
	wmi_name = []
	wmi_pid = []
	for i in range(len(wmist)):
		a = i % 2
		if a == 0:
			wmi_name.append(wmist[i])
		else:
			wmi_pid.append(wmist[i])
	for i in range(5):
		wmi_name.pop(0)	
		wmi_pid.pop(0)	
	for i in range(len(wmi_name)):
		pid = int(wmi_pid[i])
		process_name = wmi_name[i]
	#	rule5 = _rule_05_(pid)
	#	rule6 = _rule_06_(process_name, pid)
		rule5 = None
		rule6 = None

		if rule5 != None:
			print(rule5)
			print(".-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.")
		if rule6 != None:
			print(rule6)
			print(".-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.")

				
main()