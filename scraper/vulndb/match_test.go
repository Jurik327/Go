package vulndb

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCpeFriendlyProductName(t *testing.T) {
	testcases := []struct {
		DisplayName string
		Vendor      string
		Expected    string
	}{
		{DisplayName: "Active Directory Authentication Library for SQL Server", Vendor: "microsoft", Expected: "active_directory_authentication_library_for_sql_server"},
		{DisplayName: "adaptive_security_appliance_software", Vendor: "cisco", Expected: "adaptive_security_appliance_software"},
		{DisplayName: "Adobe Acrobat Reader DC", Vendor: "adobe", Expected: "acrobat_reader_dc"},
		{DisplayName: "Adobe Acrobat XI Pro", Vendor: "adobe", Expected: "acrobat_xi_pro"},
		{DisplayName: "Adobe Creative Cloud", Vendor: "adobe", Expected: "creative_cloud"},
		{DisplayName: "AirPort", Vendor: "apple", Expected: "airport"},
		{DisplayName: "Apple Application Support (32-bit)", Vendor: "apple", Expected: "application_support"},
		{DisplayName: "Apple Application Support (64-bit)", Vendor: "apple", Expected: "application_support"},
		{DisplayName: "Apple Mobile Device Support", Vendor: "apple", Expected: "mobile_device_support"},
		{DisplayName: "Apple Software Update", Vendor: "apple", Expected: "software_update"},
		{DisplayName: "Backup and Sync from Google", Vendor: "google", Expected: "backup_and_sync_from"},
		{DisplayName: "Bonjour", Vendor: "apple", Expected: "bonjour"},
		{DisplayName: "Cisco AnyConnect Secure Mobility Client ", Vendor: "cisco", Expected: "anyconnect_secure_mobility_client"},
		{DisplayName: "database_server", Vendor: "oracle", Expected: "database_server"},
		{DisplayName: "Dropbox", Vendor: "dropbox", Expected: "dropbox"},
		{DisplayName: "GIMP 2.8.22", Vendor: "gimp", Expected: "gimp"},
		{DisplayName: "Git version 2.14.1", Vendor: "git", Expected: "git"},
		{DisplayName: "Google Chrome", Vendor: "google", Expected: "chrome"},
		{DisplayName: "iCloud", Vendor: "apple", Expected: "icloud"},
		{DisplayName: "IIS 10.0 Express", Vendor: "microsoft", Expected: "iis_express"},
		{DisplayName: "Intel(R) Management Engine Components", Vendor: "intel", Expected: "management_engine_components"},
		{DisplayName: "Intel(R) Processor Graphics", Vendor: "intel", Expected: "processor_graphics"},
		{DisplayName: "Intel(R) Rapid Storage Technology", Vendor: "intel", Expected: "rapid_storage_technology"},
		{DisplayName: "ios", Vendor: "cisco", Expected: "ios"},
		{DisplayName: "iTunes", Vendor: "apple", Expected: "itunes"},
		{DisplayName: "JetBrains Gogland 172.3968.45", Vendor: "jetbrains", Expected: "gogland"},
		{DisplayName: "JetBrains GoLand 2018.1.5", Vendor: "jetbrains", Expected: "goland"},
		{DisplayName: "JetBrains GoLand 2018.2.1", Vendor: "jetbrains", Expected: "goland"},
		{DisplayName: "JetBrains PyCharm 2018.1.3", Vendor: "jetbrains", Expected: "pycharm"},
		{DisplayName: "JetBrains WebStorm 2018.2.4", Vendor: "jetbrains", Expected: "webstorm"},
		{DisplayName: "Microsoft Azure Authoring Tools - v2.9.5.3", Vendor: "microsoft", Expected: "azure_authoring_tools"},
		{DisplayName: "Microsoft Azure Compute Emulator - v2.9.5.3", Vendor: "microsoft", Expected: "azure_compute_emulator"},
		{DisplayName: "Microsoft Azure Libraries for .NET – v2.9", Vendor: "microsoft", Expected: "azure_libraries_for_.net"},
		{DisplayName: "Microsoft Azure Mobile App SDK V3.0", Vendor: "microsoft", Expected: "azure_mobile_app_sdk"},
		{DisplayName: "Microsoft Azure Storage Emulator - v5.1", Vendor: "microsoft", Expected: "azure_storage_emulator"},
		{DisplayName: "Microsoft Baseline Security Analyzer 2.3", Vendor: "microsoft", Expected: "baseline_security_analyzer"},
		{DisplayName: "Microsoft Help Viewer 2.2", Vendor: "microsoft", Expected: "help_viewer"},
		{DisplayName: "Microsoft Identity Extensions", Vendor: "microsoft", Expected: "identity_extensions"},
		{DisplayName: "Microsoft .NET Framework 4.5.1 SDK", Vendor: "microsoft", Expected: ".net_framework_sdk"},
		{DisplayName: "Microsoft ODBC Driver 13 for SQL Server", Vendor: "microsoft", Expected: "odbc_driver_13_for_sql_server"},
		{DisplayName: "Microsoft SQL Server 2012 Native Client ", Vendor: "microsoft", Expected: "sql_server_2012_native_client"},
		{DisplayName: "Microsoft SQL Server Data-Tier Application Framework (x86)", Vendor: "microsoft", Expected: "sql_server_data_tier_application_framework"},
		{DisplayName: "Microsoft SQL Server Management Studio - 17.7", Vendor: "microsoft", Expected: "sql_server_management_studio"},
		{DisplayName: "Microsoft Visual C++ 2005 Redistributable", Vendor: "microsoft", Expected: "visual_c++_2005_redistributable"},
		{DisplayName: "Microsoft Visual Studio 2017", Vendor: "microsoft", Expected: "visual_studio_2017"},
		{DisplayName: "Microsoft Visual Studio Code", Vendor: "microsoft", Expected: "visual_studio_code"},
		{DisplayName: "MobaXterm", Vendor: "mobatek", Expected: "mobaxterm"},
		{DisplayName: "Mozilla Firefox 61.0 (x64 en-US)", Vendor: "mozilla", Expected: "firefox"},
		{DisplayName: "mRemoteNG", Vendor: "next_generation_software", Expected: "mremoteng"},
		{DisplayName: "Node.js", Vendor: "nodejs", Expected: "node.js"},
		{DisplayName: "NoMachine", Vendor: "nomachine", Expected: "nomachine"},
		{DisplayName: "Npcap 0.93", Vendor: "nmap", Expected: "npcap"},
		{DisplayName: "NVIDIA 3D Vision Driver 391.25", Vendor: "nvidia", Expected: "3d_vision_driver"},
		{DisplayName: "NVIDIA Graphics Driver 391.25", Vendor: "nvidia", Expected: "graphics_driver"},
		{DisplayName: "OpenVPN 2.4.4-I601 ", Vendor: "openvpn", Expected: "openvpn"},
		{DisplayName: "Oracle VM VirtualBox 5.2.18", Vendor: "oracle", Expected: "vm_virtualbox"},
		{DisplayName: "Orca", Vendor: "microsoft", Expected: "orca"},
		{DisplayName: "Python Launcher", Vendor: "python_software_foundation", Expected: "python_launcher"},
		{DisplayName: "Realtek Card Reader", Vendor: "realtek", Expected: "card_reader"},
		{DisplayName: "Realtek High Definition Audio Driver", Vendor: "realtek", Expected: "high_definition_audio_driver"},
		{DisplayName: "TeamViewer 12", Vendor: "teamviewer", Expected: "teamviewer_12"},
		{DisplayName: "Tenable Nessus (x64)", Vendor: "tenable", Expected: "nessus"},
		{DisplayName: "Vagrant", Vendor: "hashicorp", Expected: "vagrant"},
		{DisplayName: "VLC media player", Vendor: "videolan", Expected: "vlc_media_player"},
		{DisplayName: "VMware Workstation", Vendor: "vmware", Expected: "workstation"},
		{DisplayName: "VNC Viewer 6.17.1113", Vendor: "realvnc", Expected: "vnc_viewer"},
		{DisplayName: "Windows SDK AddOn", Vendor: "microsoft", Expected: "windows_sdk_addon"},
		{DisplayName: "WinRAR 5.50 (64-bit)", Vendor: "rarlab", Expected: "winrar"},
		{DisplayName: "WinSCP 5.11.1", Vendor: "winscp", Expected: "winscp"},
	}

	for _, tcase := range testcases {
		cpeFriendly := prepProductName(tcase.DisplayName, tcase.Vendor)
		if cpeFriendly != tcase.Expected {
			t.Fatalf("'%s' != '%s' (%s)", cpeFriendly, tcase.Expected, tcase.DisplayName)
		}
	}
}

func TestMatchingPerformance(t *testing.T) {
	vdbPath := os.Getenv(`VULNDB_PATH`)
	if len(vdbPath) == 0 {
		t.Skipf("Skipped, VULNDB_PATH not set")
		return
	}

	vdb, err := New(vdbPath)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer vdb.Close()

	vdbSession, err := vdb.NewSession()
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer vdbSession.Close()

	testcases := []struct {
		Publisher      string
		DisplayName    string
		DisplayVersion string
	}{
		{`Google Inc.`, `Google Chrome`, `62.0.3202.94`},
		{`Google, Inc.`, `Google Chrome`, `70.0.3538.102`},
	}

	for _, tcase := range testcases {
		start := time.Now()
		cves, err := MatchCVEs(vdbSession, "a", tcase.Publisher, tcase.DisplayName, tcase.DisplayVersion, "", "")
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		end := time.Now()
		diff := end.Sub(start)
		t.Logf("%v - %d CVEs - took %s", tcase.DisplayName, len(cves), diff)
	}
}

func TestMatchingPerformance2(t *testing.T) {
	vdbPath := os.Getenv(`VULNDB_PATH`)
	if len(vdbPath) == 0 {
		t.Skipf("Skipped, VULNDB_PATH not set")
		return
	}

	vdb, err := New(vdbPath)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer vdb.Close()

	vdbSession, err := vdb.NewSession()
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer vdbSession.Close()

	testcases := []struct {
		Publisher   string
		DisplayName string
		Vendor      string
		Product     string
	}{
		{`Google Inc.`, `Google Chrome`, `google`, `chrome`},
		{`Google, Inc.`, `Google Chrome`, `google`, `chrome`},
		{`Igor Pavlov`, `7-Zip 15.14 (x64 edition)`, `igor_pavlov`, `7-zip`},
		{`Igor Pavlov`, `7-Zip 9.20 (x64 edition)`, `igor_pavlov`, `7-zip`},
		{"Adobe Systems Incorporated", "Adobe Acrobat Reader DC", "adobe", "acrobat_reader_dc"},
		{"Adobe Systems Incorporated", "Adobe Acrobat DC", "adobe", "acrobat_dc"},
		{"Adobe Systems Incorporated", "Adobe AIR", "adobe", "air"},
		{"Adobe Systems, Inc.", "Adobe Shockwave Player 12.3", "adobe", "shockwave_player"},
		{"Mozilla", "Mozilla Firefox 58.0.1 (x64 en-US)", "mozilla", "firefox"},
		{"Mozilla", "Mozilla Firefox 52.5.0 ESR (x64 en-US)", "mozilla", "firefox_esr"},
		{"TeamViewer", "TeamViewer 12", "teamviewer", "teamviewer"},
		{"VideoLAN", "VLC media player", "videolan", "vlc_media_player"},
		{"HP", "HP Support Assistant", "hp", "support_assistant"},
		{"Dropbox, Inc.", "Dropbox", "dropbox", "dropbox"},
		{"Apple Inc.", "Bonjour", "apple", "bonjour"},
		{"Apple Inc.", "iTunes", "apple", "itunes"},
		{"Adobe Systems Incorporated", "Adobe Creative Cloud", "adobe", "creative_cloud"},
		{"The Git Development Community", "Git version 2.14.1", "git", "git"},
		{"Adobe Systems, Inc.", "Adobe ColdFusion 10", "adobe", "coldfusion"},
		{"TechSmith Corporation", "Snagit 11", "techsmith", "snagit"},
		{"Audacity Team", "Audacity 2.1.3", "audacityteam", "audacity"},
		{"Irfan Skiljan", "IrfanView 4.50 (64-bit)", "irfanview", "irfanview"},
		{"Fortinet Inc", "FortiClient", "fortinet", "forticlient"},
		{"Huawei Technologies Co.,Ltd", "Mobile Broadband HL Service", "huawei", "mobile_broadband_hl_service"},
		{"Hewlett-Packard Development Company, L.P.", "HP Insight Diagnostics  Online Edition for Windows", "hp", "insight_diagnostics"},
		{"win.rar GmbH", "WinRAR 5.40 beta 3 (64-bit)", "rarlab", "winrar"},
		{"The Wireshark developer community, https://www.wireshark.org", "Wireshark 2.4.4 64-bit", "wireshark", "wireshark"},
		{`Autodesk, Inc.`, `Autodesk Design Review 2013`, `autodesk`, `design_review`},
		{"Autodesk", "Autodesk AutoCAD 2016 - English", "autodesk", "autocad"},
		{"Autodesk", "Autodesk Autodesk AutoCAD Map 3D 2014", "autodesk", "autocad_map_3d"},
		{"Autodesk", "Autodesk AutoCAD LT 2014 - English", "autodesk", "autocad_lt"},
		{"Autodesk", "Autodesk AutoCAD Electrical 2019 - English", "autodesk", "autocad_electrical"},
		{"Foxit Software Inc.", "Foxit PhantomPDF", "foxitsoftware", "phantompdf"},
		{"Foxit Software Inc.", "Foxit PhantomPDF Standard", "foxitsoftware", "phantompdf"},
		{"Foxit Software Inc.", "Foxit Reader", "foxitsoftware", "reader"},
		{"Simon Tatham", "PuTTY release 0.70 (64-bit)", "simon_tatham", "putty"},
	}

	for _, tcase := range testcases {
		t.Logf(`%s/%s`, tcase.Publisher, tcase.DisplayName)
		products, err := ListProductByTitles(vdbSession, tcase.Publisher, tcase.DisplayName)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		if products == nil {
			t.Fatalf("No match")
		}
		if len(products.Products) != 1 {
			t.Logf("Products: %#v", products.Products)
			t.Fatalf("len(products) != 1 (got %d)", len(products.Products))
		}

		product := products.Products[0]
		if product.ProductName != tcase.Product {
			t.Fatalf("ProductName incoreect (%s != %s)", product.ProductName, tcase.Product)
		}
		if product.VendorName != tcase.Vendor {
			t.Fatalf("ProductName incoreect (%s != %s)", product.ProductName, tcase.Product)
		}
	}
}

func TestVulnerabilityMatching(t *testing.T) {
	vdbPath := os.Getenv(`VULNDB_PATH`)
	if len(vdbPath) == 0 {
		t.Skipf("Skipped, VULNDB_PATH not set")
		return
	}

	vdb, err := New(vdbPath)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer vdb.Close()

	vdbSession, err := vdb.NewSession()
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer vdbSession.Close()

	testcases := []struct {
		Publisher      string
		DisplayName    string
		DisplayVersion string
		Patch          string
		CVEList        []string
	}{
		{"Adobe Systems, Inc.", "Adobe ColdFusion 11", "11.0.0.0", "", []string{}},
	}

	for _, tcase := range testcases {
		matches, err := MatchCVEs(vdbSession, "a", tcase.Publisher, tcase.DisplayName, tcase.DisplayVersion, tcase.Patch, "")
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		cveList := []string{}
		for _, match := range matches {
			cveList = append(cveList, match.Advisory.CVEID)
		}
		if !reflect.DeepEqual(cveList, tcase.CVEList) {
			t.Logf("%+v != %+v", cveList, tcase.CVEList)
			t.Fatalf("Error mismatching cveList")
		}
	}
}

func TestVulnerabilityMatchingCPE(t *testing.T) {
	vdbPath := os.Getenv(`VULNDB_PATH`)
	if len(vdbPath) == 0 {
		t.Skipf("Skipped, VULNDB_PATH not set")
		return
	}

	vdb, err := New(vdbPath)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer vdb.Close()

	vdbSession, err := vdb.NewSession()
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer vdbSession.Close()

	testcases := []struct {
		CPE     string
		CVEList []string
	}{
		// Junos 12.1x46.
		{"cpe:/o:juniper:junos:12.1x46:d15", []string{"CVE-2016-1261", "CVE-2016-1279", "CVE-2017-2345", "CVE-2018-0001", "CVE-2018-0007"}},
		{"cpe:/o:juniper:junos:12.1x46:d50", []string{"CVE-2016-1279", "CVE-2017-2345", "CVE-2017-2349", "CVE-2018-0001", "CVE-2018-0007"}},
		{"cpe:/o:juniper:junos:12.1x46:d60", []string{"CVE-2017-2345", "CVE-2018-0001", "CVE-2018-0007", "CVE-2018-0025", "CVE-2018-0045"}},
		{"cpe:/o:juniper:junos:12.1x46:d70", []string{"CVE-2018-0003", "CVE-2019-0033"}},
		{"cpe:/o:juniper:junos:12.1x46:d71", []string{"CVE-2019-0012", "CVE-2019-0013", "CVE-2019-0044"}},
		{"cpe:/o:juniper:junos:12.1x46:d80", []string{}},
		{"cpe:/o:juniper:junos:12.1x46:d100", []string{}},
		// Junos 15.1x49.
		{"cpe:/o:juniper:junos:15.1x49:d10", []string{"CVE-2016-1261", "CVE-2016-1279", "CVE-2017-2345", "CVE-2018-0001", "CVE-2018-0007"}},
		{"cpe:/o:juniper:junos:15.1x49:d20", []string{"CVE-2016-1279", "CVE-2017-2341", "CVE-2017-2345", "CVE-2018-0001", "CVE-2018-0007"}},
		{"cpe:/o:juniper:junos:15.1x49:d40", []string{"CVE-2017-2341", "CVE-2017-2343", "CVE-2017-2345", "CVE-2018-0007", "CVE-2018-0021"}},
		{"cpe:/o:juniper:junos:15.1x49:d60", []string{"CVE-2017-2341", "CVE-2017-2345", "CVE-2018-0007", "CVE-2018-0021", "CVE-2018-0043"}},
		{"cpe:/o:juniper:junos:15.1x49:d80", []string{"CVE-2017-2345", "CVE-2018-0007", "CVE-2018-0021", "CVE-2018-0043", "CVE-2018-0045"}},
		{"cpe:/o:juniper:junos:15.1x49:d100", []string{"CVE-2017-10605", "CVE-2018-0020", "CVE-2018-0043", "CVE-2018-0045", "CVE-2018-0052"}},
		{"cpe:/o:juniper:junos:15.1x49:d140", []string{"CVE-2018-0031", "CVE-2018-0049", "CVE-2018-0052", "CVE-2019-0013", "CVE-2019-0044"}},
		{"cpe:/o:juniper:junos:15.1x49:d150", []string{"CVE-2019-0044"}},
		{"cpe:/o:juniper:junos:15.1x49:d160", []string{}},
		// Cisco ASA.
		{"cpe:/a:cisco:adaptive_security_appliance_software:9.5(1)201", []string{"CVE-2018-0101", "CVE-2018-0228", "CVE-2018-0296", "CVE-2018-15465"}},
		{"cpe:/a:cisco:adaptive_security_appliance_software:9.995(1)201", []string{}},
		// VLC (ios specific issue).
		{"cpe:2.3:a:videolan:vlc_media_player:3.0.0:::::windows::", []string{}},
		{"cpe:2.3:a:videolan:vlc_media_player:3.0.0:::::ios::", []string{"CVE-2018-19937"}},
		{"cpe:2.3:a:videolan:vlc_media_player:3.1.5:::::ios::", []string{}},
		{"cpe:2.3:a:videolan:vlc_media_player:3.0.0:::::::", []string{}},
		{"cpe:2.3:a:videolan:vlc_media_player:3.0.0:::::miggi::", []string{}},
	}

	for _, tcase := range testcases {
		cpeParts, err := ParseCPE(tcase.CPE)
		require.NoError(t, err)

		matches, err := MatchCVEs(vdbSession, cpeParts.Systype, cpeParts.Vendor, cpeParts.Product, cpeParts.Version, cpeParts.Patch, cpeParts.TargetSW)
		require.NoError(t, err)

		cveList := []string{}
		for _, match := range matches {
			cveList = append(cveList, match.Advisory.CVEID)
		}
		require.Equal(t, tcase.CVEList, cveList, "CPE: %s", tcase.CPE)
	}
}
