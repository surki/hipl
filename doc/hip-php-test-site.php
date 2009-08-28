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
	$title = "Our Own Webmail";
	
	echo ("
	<html><head><title>$title</title></head>
	<body bgColor='#9Cc4c7' link='#a0a000' text='#1A4C50' vLink='#a000a0'>
	");
	
	if ($index >= 6)
	{
		echo ("
		<h3><center>$title</center></h3><hr>
		<center>
		<a href='index.php?index=6'>|Inbox|</a>
		<a href='index.php?index=7'>|Trash|</a>
		<a href='index.php?index=8'>|Compose|</a>
		<a href='index.php?index=9'>|Preferences|</a>
		<a href='index.php?index=1'>|Logout|</a>
		<hr>");
		
		if ($index == 6) echo ("<font color='#303030'>Inbox is empty.</font>");
		if ($index == 7) echo ("<font color='#303030'>Trash is empty.</font>");
		if ($index == 8) echo ("<font color='#903030'>Failure when connecting to server!</font>");
		if ($index == 9) echo ("<font color='#903030'>Failure when connecting to server!</font>");
		
		echo ("<br />");
	}
	else
	{
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
		
		if ($index == 2)
		{
			echo ("<font color='#ff5050'><h3>Login failed, try again</h3></font><b>Enter your email account and current password:</b>");
		}
		else
		{
			echo ("<h3>Log in</h3><b>Enter your email account and current password:</b>");
		}
		
		echo ("
					</td>
				</tr>
		
				<tr>
					<td>Account:</td>
					<td><input type='text' name='form_username' /></td>
				</tr>
		
				<tr>
					<td>Password:</td>
					<td><input type='password' name='form_password' /></td>
				</tr>
		
				<tr>
					<td colspan='2' align='center'>
					<input type='submit' name='login' value='Login' />
					</td>
				</tr>
			</table>
		</form>
		</p></center>
		");
	}
	
	if ($index == 5 || $using_hip == 1)
	echo ("
		<br /><hr>
		<p><center>This connection is secured and encrypted by
		<a href='index.php?index=100'><font color='#2040e0'>HIP</font></a>.</center>
		<center><font>Server HIT is $server_hit.</font></center></p>
		");
	else
	echo ("
		<br /><br /><hr>
		<center><p>This connection is insecure. Please enable
		HIP.</p></center>
		");
}
else
{
	echo ("
		<html><head><title>What is HIP?</title></head>
		<body bgColor='#aCe4e7' link='#a0a000' text='#1A4C50' vLink='#a000a0'>
		
	      <br /><h1>InfraHIP Overview</h1>
	      
	      <p>The Host Identity Protocol (HIP) (In Chinese: zhu-ji shi-bie xie-yi) and the related architecture form a proposal to change the TCP/IP stack to securely support mobility and multi-homing. Additionally, they provide for enhanced security and privacy and advanced network concepts, such as moving networks and mobile ad hoc networks. The InfraHIP project studies application related aspects of HIP, including APIs, rendezvous service, operating system security, multiple end-points within a single host, process migration, and issues related to enterprise-level solutions. Through this, the project maintains HIIT (and thereby Finland) as one of the leading research centers doing HIP related work.</p>
	      
	      <br /><h1>Infrastructure for HIP (InfraHIP)</h1>
	
	      <p>18.11.2004. The National Technology Agency TEKES awarded first-year funding for the project InfraHIP. The project is led by Professor Martti Mäntylä with Professor Antti Ylä-Jääski from the TML laboratory at TKK. Dr. Andrei Gurtov will work as the project manager. The industrial partners of the project are Nokia, Ericsson, Elisa and Finnish Defence Forces. The work will be executed in close co-operation with Prof. Scott Shenker and Prof. Ion Stoica from the University of California at Berkeley.</p>
	      <p>'Infra' in the project name stands for Infrastructure. As the basic HIP protocol is almost ready, the project focuses on developing the missing infrastructure pieces such as DNS, NAT, and firewall support to enable a widespread deployment of HIP.</p>
		");
}

echo ("</body></html>");

?>
