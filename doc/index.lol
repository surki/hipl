<?

$using_hip = 0;
$domain = $_SERVER['REMOTE_ADDR'];
$server_hit = $_SERVER['SERVER_ADDR'];
if (substr($domain, 0, 6) == "2001:1")
{
	$using_hip = 1;
}

$index = $_GET['index'];

if ($index == null)
{
	$index = 1;
}

if ($index < 100)
{
	$title = "Welcome to the Testing Page of InfraHIP II";
	
	echo ("
	<html><head><title>$title</title></head>
	<body link='#a0a000' text='#1A4C50' vLink='#a000a0'>
	");
	
	 echo ("
	<br /><br />
	<hr>
	<h2><center>$title</center></h2>
	<hr>
	
	<h4>
	<center><p>
	<form method='post' action='index.php?index=6'>
	<table>
		<tr>
			<td colspan='2'>
	");
	
	if ($using_hip == 1)
	echo ("
		<br /><hr>
		<p><center>This connection is secured and encrypted by
		<a href='index.lol?index=100'><font color='#2040e0'>HIP</font></a>.</center>
		<center><font>Client HIT is $domain</font></center>
		<center><font>Server HIT is $server_hit</font></center></p>

        ");
	else
	echo ("
		<br /><br /><hr>
		<center><p>This connection is insecure. Please enable
		HIP or the bad guys will come for you.</p></center>
                <center><font>Client IP is $domain</font></center></p>
                <center><font>Server IP is $server_hit</font></center>

	");
}
else
{
	echo ("
		<html><head><title>What is HIP?</title></head>
		<body link='#a0a000' text='#1A4C50' vLink='#a000a0'>
		
	      <br /><h1>InfraHIP Overview</h1>
	      
	      <p>The Host Identity Protocol (HIP) (In Chinese: zhu-ji shi-bie xie-yi) and the related architecture form a proposal to change the TCP/IP stack to securely support mobility and multi-homing. Additionally, they provide for enhanced security and privacy and advanced network concepts, such as moving networks and mobile ad hoc networks. The InfraHIP project studies application related aspects of HIP, including APIs, rendezvous service, operating system security, multiple end-points within a single host, process migration, and issues related to enterprise-level solutions. Through this, the project maintains HIIT (and thereby Finland) as one of the leading research centers doing HIP related work.</p>
	      
	      <br /><h1>Infrastructure for HIP (InfraHIP)</h1>
	
	      <p>18.11.2004. The National Technology Agency TEKES awarded first-year funding for the project InfraHIP. The project is led by Professor Martti Mäntylä with Professor Antti Ylä-Jääski from the TML laboratory at TKK. Dr. Andrei Gurtov will work as the project manager. The industrial partners of the project are Nokia, Ericsson, Elisa and Finnish Defence Forces. The work will be executed in close co-operation with Prof. Scott Shenker and Prof. Ion Stoica from the University of California at Berkeley.</p>
	      <p>'Infra' in the project name stands for Infrastructure. As the basic HIP protocol is almost ready, the project focuses on developing the missing infrastructure pieces such as DNS, NAT, and firewall support to enable a widespread deployment of HIP.</p>
		");
}

echo ("</body></html>");

?>
