#pragma  comment(linker,"/OPT:NOWIN98")
#include "Athena.h"
HWND           hWnd;
HANDLE         hthread;
T_PRAM         th_prama;
pcap_t         *devpoint;
pcap_if        *alldevs; // define the list of the Network adapter device
HINSTANCE      Cryptdll;
MD5Init_T      MD5Init;
MD5Final_T     MD5Final;
MD5Update_T    MD5Update;
unsigned char  lstatus;
char           PATH[PCAP_ERRBUF_SIZE];   // Program path
char           errbuf[PCAP_ERRBUF_SIZE]; // PCAP_ERRBUF_SIZE is 256
unsigned char  buff[PCAP_ERRBUF_SIZE];   // Send Buffer
AUTH_HDR       ahdr = {{'\x01','\x80','\xc2','\x00','\x00','\x03'}, "", {'\x88','\x8e'}, '\x02', '\x00', 0};
AUTH_EXT       ehdr = {'\x02', '\x01', 0, '\x01', NULL};
NOTIFYICONDATA nd = {sizeof(NOTIFYICONDATA),NULL,IDI_ICON,NIF_ICON|NIF_MESSAGE|NIF_TIP,WM_NOTIFYICON,NULL,"802.1x拨号器"};
void print(char *t,unsigned char *bf,int n) {
	printf("-----------------------------------------------\n%s%d\n",t,n);
	for(int i=0;i<n;i++) {
		if(i%16==0 && i!=0) printf("\n");
		printf("%02x ",bf[i]);
	}
	printf("\n-----------------------------------------------\n");
}
inline void StatusUI(HWND hWnd, const char *status, char c) {
	lstatus = c;
	SetDlgItemText(hWnd,IDC_STATUS,status);
}
void buildpacket(char c,AUTH_HDR *ahdr, AUTH_EXT *ehdr, unsigned char pkgid, unsigned n) {
	if(c=='e' || c=='s') {
		ahdr->length   = 0;
		ahdr->type     = (c=='s') ? '\x01' : '\x02';
		ehdr->nouse[0] = ehdr->nouse[1] = sizeof(AUTH_HDR);
	}
	else if(c=='c' || c=='i') {
		ahdr->type     = '\x00';
		ahdr->length   = (c=='i') ? htons(n+5) : htons(n+6);
		ehdr->type     = (c=='i') ? '\x01' : '\x04';
		ehdr->length   = ahdr->length;
		ehdr->id       = pkgid;
		ehdr->code     = '\x02';
		ehdr->nouse[0] = (c=='i') ? '\x00' : '\x01';
		ehdr->nouse[1] = sizeof(AUTH_HDR)+sizeof(AUTH_EXT)-sizeof(ehdr->nouse)-sizeof(ehdr->identity)+ehdr->nouse[0]+n;
	}
	else return;
	memcpy(buff, ahdr, sizeof(AUTH_HDR));
	if(c=='c' || c=='i') {
		memcpy(buff+sizeof(AUTH_HDR), ehdr, sizeof(AUTH_EXT)-sizeof(ehdr->nouse)-sizeof(ehdr->identity));
		memcpy(buff+sizeof(AUTH_HDR)+sizeof(AUTH_EXT)-sizeof(ehdr->nouse)-sizeof(ehdr->identity), &n, ehdr->nouse[0]);
		memcpy(buff+sizeof(AUTH_HDR)+sizeof(AUTH_EXT)-sizeof(ehdr->nouse)-sizeof(ehdr->identity)+ehdr->nouse[0], ehdr->identity, n);
	}
	//print("build:",buff,ehdr->nouse[1]);
	pcap_sendpacket(devpoint, buff, ehdr->nouse[1]);
}
void packet_handler(unsigned char *t, const struct pcap_pkthdr *pkt_header, const unsigned char *pkt_data) {
#ifdef _DEBUG
	print("sniff:",(unsigned char *)pkt_data,pkt_header->len);
#endif
	if(pkt_header->len!=60) return;
	if(memcmp(pkt_data+0x0c, "\x88\x8e\x02\x00", 4)) return;
	if(lstatus>STATUS_PASS_SUCC) {//
		if(!memcmp(pkt_data+0x12,"\x01",1) && !memcmp(pkt_data+0x16,"\x01",1)) {
			if(lstatus==STATUS_AUTH_EXIT) StatusUI(hWnd,"STATUS_EXIT_OFF1",STATUS_EXIT_OFF1);
			else if(lstatus==STATUS_EXIT_OFF1) {
				StatusUI(hWnd,"STATUS_EXIT_SUCC",STATUS_EXIT_SUCC);
				pcap_breakloop(devpoint);
			}
		}
		return;
	}
	memcpy(&((char*)&ahdr.length)[0], pkt_data+0x11, 1);
	memcpy(&((char*)&ahdr.length)[1], pkt_data+0x10, 1);
	if((ehdr.length=ahdr.length) < 5) {
		if(!memcmp(pkt_data+0x12,"\x03",1)) StatusUI(hWnd,"STATUS_PASS_SUCC",STATUS_PASS_SUCC);
		if(!memcmp(pkt_data+0x12,"\x04",1)) { // Code: Failure (4)
			if(lstatus==STATUS_SEND_USER) StatusUI(hWnd,"STATUS_USER_FAIL",STATUS_USER_FAIL);
			if(lstatus==STATUS_SEND_PASS) StatusUI(hWnd,"STATUS_PASS_FAIL",STATUS_PASS_FAIL);
		}
	}
	if(!memcmp(pkt_data+0x12,"\x01",1)) {     // Code: Request (1)
		if(!memcmp(pkt_data+0x16,"\x01",1)) { // Type: Identity [RFC3748] (1)
			if(lstatus==STATUS_AUTH_STAR) StatusUI(hWnd,"STATUS_NEED_USER",STATUS_NEED_USER);
			ehdr.identity = (unsigned char *)(((T_PRAM*)t)->usr);
			buildpacket('i', &ahdr, &ehdr, *(pkt_data+0x13), strlen((char*)(((T_PRAM*)t)->usr)));
			if(lstatus==STATUS_NEED_USER) StatusUI(hWnd,"STATUS_SEND_USER",STATUS_SEND_USER);
		}
		if(!memcmp(pkt_data+0x16,"\x04",1)) { // Type: MD5-Challenge [RFC3748] (4)
			StatusUI(hWnd,"STATUS_NEED_PASS",STATUS_NEED_PASS);
			unsigned char res[20];
			CalculateMD5(*((char*)(pkt_data+0x13)), (unsigned char *)(((T_PRAM*)t)->pwd), strlen((char*)(((T_PRAM*)t)->pwd)), (unsigned char *)(pkt_data+0x18), *(pkt_data+0x17), res);
			ehdr.identity = res;
			buildpacket('c', &ahdr, &ehdr, *(pkt_data+0x13), strlen((char*)ehdr.identity));
			StatusUI(hWnd,"STATUS_SEND_PASS",STATUS_SEND_PASS);
		}
	}
}
void pcap_Init(pcap_if *d){
	struct bpf_program fcode;
	char filter[] = "ether proto 0x888e";
	if(!(devpoint=pcap_open_live(d->name,65535,1,10,errbuf))) {
		MessageBox(NULL,errbuf,"pcap_open_live()",MB_OK);
		pcap_freealldevs(alldevs);
		exit(1);
	}
	if(pcap_datalink(devpoint) != DLT_EN10MB) {
		MessageBox(NULL,"This program works only on Ethernet network.","pcap_datalink()",MB_OK);
		pcap_freealldevs(alldevs);
		exit(1);
	}
	if (pcap_compile(devpoint, &fcode, filter, 1, 0xffffffff) < 0) {
		MessageBox(NULL,"Unable to compile the packet filter.","pcap_compile()",MB_OK);
		pcap_freealldevs(alldevs);
		exit(1);
	}
	if (pcap_setfilter(devpoint, &fcode) < 0) {
		MessageBox(NULL,"Error setting the filter.","pcap_compile()",MB_OK);
		pcap_freealldevs(alldevs);
		exit(1);
	}
}
DWORD WINAPI Recvpacket(void *t){
	buildpacket('s', &ahdr, &ehdr, '\x01', 0);        // Build and send Start Packet
	pcap_loop(devpoint, 0, packet_handler, (unsigned char *)t);
	pcap_close(devpoint);
	ExitThread(0);
}
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam){
	if(message==WM_SYSCOMMAND && (wParam==SC_MINIMIZE || wParam==SC_CLOSE)) return ShowWindow(hWnd,SW_HIDE);
	switch (message){
		case WM_NOTIFYICON:
			switch(lParam) {
				case WM_LBUTTONDBLCLK:
					ShowWindow(hWnd,SW_SHOW);
					break;
				case WM_RBUTTONDOWN:
					HMENU mMenu = LoadMenu(NULL,(LPCTSTR)IDR_TRAY);
					HMENU pMenu = GetSubMenu(mMenu,0);
					POINT point;
					GetCursorPos(&point);
					SetMenuDefaultItem(pMenu,0,true);
					SetForegroundWindow(nd.hWnd);
					TrackPopupMenu(pMenu,TPM_LEFTALIGN|TPM_RIGHTBUTTON,point.x,point.y,0,hWnd,NULL);
					break;
			}
			break;
		case WM_COMMAND:
			switch (LOWORD(wParam)){
				case IDC_LOGIN:
					if(!IsDlgButtonChecked(hWnd,IDC_LOGIN)) {
						if(lstatus==STATUS_PASS_SUCC) { // 如果已经认证成功
							buildpacket('e', &ahdr, &ehdr, '\x01', 0); // Build and send logoff packet
							StatusUI(hWnd,"STATUS_AUTH_EXIT",STATUS_AUTH_EXIT);
						} else {
							pcap_breakloop(devpoint);
							StatusUI(hWnd,"",STATUS_EXIT_SUCC);
						}
						//CloseHandle(hthread);
						SetDlgItemText(hWnd,IDC_LOGIN,"Login");
						EnableWindow(GetDlgItem(hWnd,IDC_ADAPTER),true);
						EnableWindow(GetDlgItem(hWnd,IDC_LAN),true);
						EnableWindow(GetDlgItem(hWnd,IDC_USER),true);
						EnableWindow(GetDlgItem(hWnd,IDC_PWD),true);
					} else {
						char mac[20],a[10];
						StatusUI(hWnd,"STATUS_AUTH_STAR",STATUS_AUTH_STAR);
						GetDlgItemText(hWnd, IDC_USER,    th_prama.usr, 32);
						GetDlgItemText(hWnd, IDC_PWD,     th_prama.pwd, 32);
						GetDlgItemText(hWnd, IDC_ADAPTER,          mac, 20);
						sscanf(mac,"%02X-%02X-%02X-%02X-%02X-%02X",&a[0],&a[1],&a[2],&a[3],&a[4],&a[5]);
						memcpy(ahdr.src,a,6);
						if(IsDlgButtonChecked(hWnd,IDC_LAN)) strcat(th_prama.usr,"@local");
						th_prama.d = alldevs;
						int sel = ComboBox_GetCurSel(GetDlgItem(hWnd,IDC_ADAPTER));
						for(int i=0;i<sel;i++) th_prama.d=th_prama.d->next;
						pcap_Init(th_prama.d);
						hthread = CreateThread(NULL,0,Recvpacket,(void*)&th_prama,0,NULL);
						SetDlgItemText(hWnd,IDC_LOGIN,"Logoff");
						EnableWindow(GetDlgItem(hWnd,IDC_ADAPTER),false);
						EnableWindow(GetDlgItem(hWnd,IDC_LAN),false);
						EnableWindow(GetDlgItem(hWnd,IDC_USER),false);
						EnableWindow(GetDlgItem(hWnd,IDC_PWD),false);
					}
					break;
                case IDC_USER:
                    {
                        int sel = ComboBox_GetCurSel(GetDlgItem(hWnd,IDC_USER));
                        if( sel>=0 ) {
                            struct CFG cfg;
                            sprintf(cfg.usr, "P%08d", sel); //把cfg.usr当做key用
                            GetPrivateProfileString("802.1x", cfg.usr, NULL, cfg.pwd, 32, PATH);
                            SetDlgItemText(hWnd, IDC_PWD, cfg.pwd);
                        }
                    }
                    break;
				case TRAY_QUIT:
					SendMessage(hWnd,WM_DESTROY,NULL,NULL);
					break;
				default:
					return DefWindowProc(hWnd, message, wParam, lParam);
			}
			break;
		case WM_DESTROY:
            if( IDOK==MessageBox(hWnd,"您是否要退出拨号程序\n退出后会自动下线","提示",MB_OKCANCEL) ) {
                char int_str[16];
                sprintf(int_str, "%u", ComboBox_GetCurSel(GetDlgItem(hWnd,IDC_ADAPTER)));
                WritePrivateProfileString("802.1x", "DefaultAdapter", int_str, PATH);
                sprintf(int_str, "%u", ComboBox_GetCurSel(GetDlgItem(hWnd,IDC_USER)));
                WritePrivateProfileString("802.1x", "DefaultUser", int_str, PATH);
                if( IsDlgButtonChecked(hWnd,IDC_LAN) ) WritePrivateProfileString("802.1x", "DefaultLAN", "1", PATH);
                else WritePrivateProfileString("802.1x", "DefaultLAN", "0", PATH);
                if( IsDlgButtonChecked(hWnd,IDC_LOGIN) ) buildpacket('e', &ahdr, &ehdr, '\x01', 0);
                Shell_NotifyIcon(NIM_DELETE,&nd);
			    pcap_freealldevs(alldevs);
			    PostQuitMessage(0);
            }
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
   }
   return 0;
}
IP_ADAPTER_INFO getAdapters() { // 获取含有MAC地址的适配器信息 iphlpapi.h iphlpapi.lib
	unsigned long dwRetVal,ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO) malloc (ulOutBufLen);
	dwRetVal = GetAdaptersInfo(pAdapterInfo,&ulOutBufLen); // 第一次调用GetAdapterInfo获取ulOutBufLen大小
	if(dwRetVal == ERROR_BUFFER_OVERFLOW){
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*) malloc (ulOutBufLen);
		dwRetVal=GetAdaptersInfo(pAdapterInfo,&ulOutBufLen);
	}
	IP_ADAPTER_INFO pAdapter;
	if(dwRetVal == NO_ERROR) pAdapter= *pAdapterInfo;
	return pAdapter;
}
bool setIDCAdapter() { // 用winpcap获取适配器信息
	IP_ADAPTER_INFO AdapterInfo = getAdapters();
	PIP_ADAPTER_INFO pAdapter = &AdapterInfo;
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf)) { // Get the list of the device in loacal host
		MessageBox(NULL,errbuf,"pcap_findalldevs_ex()",MB_OK);
		return false;
	}
	unsigned char mac[20];
	for(pcap_if *d=alldevs;d;d=d->next) { // show the list
		if(d->name) {
			pAdapter = &AdapterInfo;
			while(pAdapter){
				if(!strstr(d->name,pAdapter->AdapterName)) {
					pAdapter = pAdapter->Next;
					continue;
				}
				sprintf((char*)mac,"%02X-%02X-%02X-%02X-%02X-%02X\0",pAdapter->Address[0],pAdapter->Address[1],pAdapter->Address[2],pAdapter->Address[3],pAdapter->Address[4],pAdapter->Address[5]);
				break;
			}
			ComboBox_AddString(GetDlgItem(hWnd,IDC_ADAPTER), mac);
		}
	}
	return true;
}
bool InitInstance(HINSTANCE hInstance, int nCmdShow){
	if( !(hWnd = CreateDialog(hInstance, (LPCTSTR)IDD_MAIN, NULL, NULL)) ) return false;
	nd.hWnd  = hWnd;
	nd.hIcon = (HICON)LoadImage(hInstance,(LPCTSTR)IDI_ICON,IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
	Shell_NotifyIcon(NIM_ADD,&nd);
	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);
	return true;
}
bool ReadIniFile() {
    struct CFG cfg;
    for(int i=0; ; i++) {
        sprintf(cfg.pwd, "U%08d", i); //把cfg.pwd当做key用
        GetPrivateProfileString("802.1x", cfg.pwd, NULL, cfg.usr, 32, PATH);
        if( strcmp(cfg.usr,"") ) ComboBox_AddString(GetDlgItem(hWnd,IDC_USER), cfg.usr);
        else break;
    }
    i = GetPrivateProfileInt("802.1x", "DefaultLAN", 0, PATH) ? 1 : 0;
    CheckDlgButton(hWnd, IDC_LAN, i);
    i = GetPrivateProfileInt("802.1x", "DefaultAdapter", 0, PATH);
    ComboBox_SetCurSel(GetDlgItem(hWnd,IDC_ADAPTER), i);
    i = GetPrivateProfileInt("802.1x", "DefaultUser", 0, PATH);
    ComboBox_SetCurSel(GetDlgItem(hWnd,IDC_USER), i);
    sprintf(cfg.usr, "P%08d", i);
    GetPrivateProfileString("802.1x", cfg.usr, NULL, cfg.pwd, 32, PATH);
    SetDlgItemText(hWnd, IDC_PWD, cfg.pwd);
    return true;
}
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG msg;
    int ret;
#ifdef _DEBUG
	AllocConsole();
	freopen("conin$", "r+t", stdin);
	freopen("conout$", "w+t", stdout);
	freopen("conout$", "w+t", stderr);
#endif
	WNDCLASSEX wc={sizeof(WNDCLASSEX),CS_CLASSDC,MainWndProc ,0L,DLGWINDOWEXTRA,hInstance,LoadIcon(hInstance,(LPCTSTR)IDI_ICON),NULL,(HBRUSH)5,NULL,"Main",NULL};
	RegisterClassEx(&wc);
	if( !InitInstance(hInstance, nCmdShow) ) return false;
    if( !LoadMD5Func(&Cryptdll, &MD5Init, &MD5Update, &MD5Final) ) return false;
    if( !setIDCAdapter() ) return false;
    if( (ret=GetModuleFileName(NULL, PATH, PCAP_ERRBUF_SIZE))>PCAP_ERRBUF_SIZE-4 ) return false; // PCAP_ERRBUF_SIZE = 256
    else strcpy(&PATH[ret-4],".ini");
    ReadIniFile();
	while (GetMessage(&msg, NULL, 0, 0)){
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return msg.wParam;
}