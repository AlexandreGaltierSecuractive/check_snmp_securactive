#!/usr/bin/perl -w
# nagios: -epn
############################## check_snmp_securactive ##############
my $Version='0.2';
# Date : 2013-01-15
# Author  : Securactive - PerformanceVison - http://securactive.net
# Help : http://securactive.net
# Licence : GPL - http://www.fsf.org/licenses/gpl.txt
# Contrib : ...
# TODO : 
#################################################################
#
# Help : ./check_snmp_securactive.pl -h
#

use strict;
use warnings;
use Net::SNMP;
use Getopt::Long;

my $TIMEOUT = 15;
my %ERRORS=('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3,'DEPENDENT'=>4);
my %REVERSE_ERRORS=reverse %ERRORS;
my %STATUS=( 1 => 'Ok', 2 => 'Warning', 3 => 'Alert', 4 => 'NA', 5 => 'Nothing', 6 => 'NotEnough' );
my $RET = 1; #Final Status

# SNMP Datas

#BCA OIDs
my $spvBCAStateTable           = '.1.3.6.1.4.1.36773.3.2.1.1';     


#Base OID : <BaseOID.index>
my @spvBCAEntries = (
my $spvBCAName                 = '.1.3.6.1.4.1.36773.3.2.1.1.1.1',
my $spvBCAStatus               = '.1.3.6.1.4.1.36773.3.2.1.1.1.2',
my $spvBCAEURT                 = '.1.3.6.1.4.1.36773.3.2.1.1.1.3',
my $spvBCASRT                  = '.1.3.6.1.4.1.36773.3.2.1.1.1.4',
my $spvBCASRTCount             = '.1.3.6.1.4.1.36773.3.2.1.1.1.5',
my $spvBCASRTCountSum          = '.1.3.6.1.4.1.36773.3.2.1.1.1.6',
my $spvBCARTTClient            = '.1.3.6.1.4.1.36773.3.2.1.1.1.7',
my $spvBCARTTServer            = '.1.3.6.1.4.1.36773.3.2.1.1.1.8',
my $spvBCADTTClient            = '.1.3.6.1.4.1.36773.3.2.1.1.1.9',
my $spvBCADTTServer            = '.1.3.6.1.4.1.36773.3.2.1.1.1.10',
my $spvBCABandwidthClient      = '.1.3.6.1.4.1.36773.3.2.1.1.1.11',
my $spvBCABandwidthServer      = '.1.3.6.1.4.1.36773.3.2.1.1.1.12',
my $spvBCATrafficClientSum     = '.1.3.6.1.4.1.36773.3.2.1.1.1.13',
my $spvBCATrafficServerSum     = '.1.3.6.1.4.1.36773.3.2.1.1.1.14',
my $spvBCAThresholdMinSRTcount = '.1.3.6.1.4.1.36773.3.2.1.1.1.15',
my $spvBCAThresholdWarning     = '.1.3.6.1.4.1.36773.3.2.1.1.1.16',
my $spvBCAThresholdAlert       = '.1.3.6.1.4.1.36773.3.2.1.1.1.17');


my @spbBCALabels = (
	"Name"		,
	"Status"	,
	"EURT"		,
	"SRT"		,
	"SRTCount"	,
	"SRTCountSum"	,
	"RTTClient"	,
	"RTTServe"	,
	"DTTClient"	,
	"DTTServer"	,
	"BWClient"	,
	"BWServer"	,
	"TrafficCSum"	,
	"TrafficSSum"	,
	"ThrMinSRTCt"	,
	"ThrWarn"	,
	"ThrAlert"	);


#BCN OIDs
my $spvBCNStateTable                         = '.1.3.6.1.4.1.36773.3.2.2.1';

#Base OID : <BaseOID.index>
my @spvBCNEntries = (
my $spvBCNName                               = '.1.3.6.1.4.1.36773.3.2.2.1.1.1',
my $spvBCNZoneA                              = '.1.3.6.1.4.1.36773.3.2.2.1.1.2',
my $spvBCNZoneB                              = '.1.3.6.1.4.1.36773.3.2.2.1.1.3',
my $spvBCNGlobalStatus                       = '.1.3.6.1.4.1.36773.3.2.2.1.1.4',
my $spvBCNStatusAtoB                         = '.1.3.6.1.4.1.36773.3.2.2.1.1.5',
my $spvBCNStatusBtoA                         = '.1.3.6.1.4.1.36773.3.2.2.1.1.6',
my $spvBCNRttAtoB                            = '.1.3.6.1.4.1.36773.3.2.2.1.1.7',
my $spvBCNRttBtoA                            = '.1.3.6.1.4.1.36773.3.2.2.1.1.8',
my $spvBCNRrAtoB                             = '.1.3.6.1.4.1.36773.3.2.2.1.1.9',
my $spvBCNRrBtoA                             = '.1.3.6.1.4.1.36773.3.2.2.1.1.10',
my $spvBCNRetransCountSumAtoB                = '.1.3.6.1.4.1.36773.3.2.2.1.1.11',
my $spvBCNRetransCountSumBtoA                = '.1.3.6.1.4.1.36773.3.2.2.1.1.12',
my $spvBCNBandwidthAtoB                      = '.1.3.6.1.4.1.36773.3.2.2.1.1.13',
my $spvBCNBandwidthBtoA                      = '.1.3.6.1.4.1.36773.3.2.2.1.1.14',
my $spvBCNTrafficSumAtoB                     = '.1.3.6.1.4.1.36773.3.2.2.1.1.15',
my $spvBCNTrafficSumBtoA                     = '.1.3.6.1.4.1.36773.3.2.2.1.1.16',
my $spvBCNPacketsCountSumAtoB                = '.1.3.6.1.4.1.36773.3.2.2.1.1.17',
my $spvBCNPacketsCountSumBtoA                = '.1.3.6.1.4.1.36773.3.2.2.1.1.18',
my $spvBCNThresholdSymetricLink              = '.1.3.6.1.4.1.36773.3.2.2.1.1.19',
my $spvBCNThresholdBandwAvailableAtoB        = '.1.3.6.1.4.1.36773.3.2.2.1.1.20',
my $spvBCNThresholdBandwAvailableBtoA        = '.1.3.6.1.4.1.36773.3.2.2.1.1.21',
my $spvBCNThresholdBandwMinAtoB              = '.1.3.6.1.4.1.36773.3.2.2.1.1.22',
my $spvBCNThresholdBandwMinBtoA              = '.1.3.6.1.4.1.36773.3.2.2.1.1.23',
my $spvBCNThresholdBandwrateWarningAtoB      = '.1.3.6.1.4.1.36773.3.2.2.1.1.24',
my $spvBCNThresholdBandwrateWarningBtoA      = '.1.3.6.1.4.1.36773.3.2.2.1.1.25',
my $spvBCNThresholdBandwrateAlertAtoB        = '.1.3.6.1.4.1.36773.3.2.2.1.1.26',
my $spvBCNThresholdBandwrateAlertBtoA        = '.1.3.6.1.4.1.36773.3.2.2.1.1.27',
my $spvBCNThresholdRttWarningAtoB            = '.1.3.6.1.4.1.36773.3.2.2.1.1.28',
my $spvBCNThresholdRttWarningBtoA            = '.1.3.6.1.4.1.36773.3.2.2.1.1.29',
my $spvBCNThresholdRttAlertAtoB              = '.1.3.6.1.4.1.36773.3.2.2.1.1.30',
my $spvBCNThresholdRttAlertBtoA              = '.1.3.6.1.4.1.36773.3.2.2.1.1.31',
my $spvBCNThresholdRrWarningAtoB             = '.1.3.6.1.4.1.36773.3.2.2.1.1.32',
my $spvBCNThresholdRrWarningBtoA             = '.1.3.6.1.4.1.36773.3.2.2.1.1.33',
my $spvBCNThresholdRrAlertAtoB               = '.1.3.6.1.4.1.36773.3.2.2.1.1.34',
my $spvBCNThresholdRrAlertBtoA               = '.1.3.6.1.4.1.36773.3.2.2.1.1.35');

my @spbBCNLabels = (
	"Name"		,
	"NameZoneA"	,
	"NameZoneB"	,
	"GlobalStatus"	,
	"StatusAtoB"	,
	"StatusBtoA"	,
	"RttAtoB"	,
	"RttBtoA"	,
	"RrAtoB"	,
	"RrBtoA"	,
	"RetCtSumAtoB"	,
	"RetCtSumBtoA"	,
	"BWAtoB"	,
	"BWAtoB"	,
	"TrafSumAtoB"	,
	"TrafSumBtoA"	,
	"PkCtSumAtoB"	,
	"PkCtSumBtoA"	,
	"ThSymetric"	,
	"ThBWAvaiAtoB"	,
	"ThBWAvaiBtoA"	,
	"ThBWMinAtoB"	,
	"ThBWMinBtoA"	,
	"ThBWRaWarAtoB"	,
	"ThBWRaWarBtoA"	,
	"ThBWRaAleAtoB"	,
	"ThBWRaAleBtoA"	,
	"ThRttWarAtoB"	,
	"ThRttWarBtoA"	,
	"ThRttAleAtoB"	,
	"ThRttAleBtoA"	,
	"ThRrWarAtoB"	,
	"ThRrWarBtoA"	,
	"ThRrAleAtoB"	,
	"ThRrAleBtoA"	);




# Globals


# Standard options
my $o_host = 		undef; 	# hostname
my $o_port = 		161; 	# port
my $o_help=		undef; 	# wan't some help ?
my $o_verb=		undef;	# verbose mode
my $o_version=		undef;	# print version
my $o_noreg=		undef;	# Do not use Regexp for name

my $o_timeout=  undef; 		# Timeout (Default 5)
# Login options specific
my $o_community = 'public'; 	# community
my $o_version2	= undef;	#use snmp v2c
my $o_login=	undef;		# Login for snmpv3
my $o_passwd=	undef;		# Pass for snmpv3
my $v3protocols=undef;	# V3 protocol list.
my $o_authproto='md5';		# Auth protocol
my $o_privproto='des';		# Priv protocol
my $o_privpass= undef;		# priv password

#Securactive Options
my $o_bca = undef;
my $o_bcn = undef;
my $o_insensitive = undef;
my $o_onlymatch = undef;


sub edit_status
{
	my $_ret = $_[0];
	if ( $RET < $_ret and $_ret <= 3 )
	{
		verb("Old Global  RET = " . $RET . "($STATUS{$RET})"," ");
		$RET=$_ret;
		verb("--- New Global RET = " . $RET .  "($STATUS{$RET})");	
	}
	else
	{
		verb("No change");
	}

}


#Get the last number of oid 
# 1.2.3.4.5.65.7 => 7
sub get_oid_index
{
	my $_oid = $_[0] ;
	my ($_return) = $_oid =~ m/.+\.(\d+)$/;
	return $_return;
}

#Get the last last number of oid
# 1.2.3.4.5.65.7 => 65
sub get_oid_entry
{
	my $_oid = $_[0] ;
	my ($_return) = $_oid =~ m/.+\.(\d+)\.\d+$/;
	return $_return;
}

sub p_version { print "check_snmp_int version : $Version\n"; }

sub print_usage {
    print "Usage: $0 [-v] -H <host> [-C <snmp_community>] [-2] | (-l login -x passwd [-X pass -L <authp>,<privp>)  [-p <port>] [-i] [-o] [-n <bcn PATERN>] [-a <bca PATERN>] [-r] [-f] [-t <timeout>] -v \n";
}


sub get_error_from_ret
{
	my $_ret = $_[0];
	my %rhash = reverse %ERRORS;
	return $rhash{($_ret - 1)};
}

sub isnnum { # Return true if arg is not a number
  my $num = shift;
  if ( $num =~ /^(\d+\.?\d*)|(^\.\d+)$/ ) { return 0 ;}
  return 1;
}

sub help {
   print "\nSNMP Network Securactive Monitor for Nagios version ",$Version,"\n";
   print "GPL licence\n\n";
   print_usage();
   print <<EOT;
-v, --verbose
   print extra debugging information
-h, --help
   print this help message
-H, --hostname=HOST
   name or IP address of host to check
-C, --community=COMMUNITY NAME
   community name for the host's SNMP agent
   default public
-l, --login=LOGIN ; -x, --passwd=PASSWD, -2, --v2c
   Login and auth password for snmpv3 authentication 
   If no priv password exists, implies AuthNoPriv 
-2, use snmp v2c
-X, --privpass=PASSWD
   Priv password for snmpv3 (AuthPriv protocol)
-L, --protocols=<authproto>,<privproto>
   <authproto> : Authentication protocol (md5|sha : default md5)
   <privproto> : Priv protocole (des|aes : default des) 
-P, --port=PORT
   SNMP port (Default 161)
-i, --insensitive
	Case insensitive for regex match
-o, --onlymatch
	Print only matched names
-a, --bca=NAME
   Name of BCA (htpp, ssh ...).
   This is treated as a regexp : -n http will match BCA http, http intranet, https, ...
   If NAME is "", will check all bca
-n, --bcn=NAME
   Name of BCN ("All - /Private/Private_fallback", ...).
   This is treated as a regexp : -n fallback will match all BNC containing "fallback".
   If NAME is "" , will check all bcn
-r, --noregexp
   Do not use regexp to match NAME
-f, --perfparse
   Perfparse compatible output.
-t, --timeout=INTEGER
   timeout for SNMP in seconds (Default: 5)   
-V, --version
   prints version number
EOT
}

#u For verbose output
sub verb 
{ 
	my ( $_out , $_endline ) = @_;
	$_endline="\n" unless ($_endline);
	print $_out,$_endline if defined($o_verb) ; 
}

sub check_options {
    Getopt::Long::Configure ("bundling");
	GetOptions(
   	'v'	=> \$o_verb,		'verbose'	=> \$o_verb,
        'h'     => \$o_help,    	'help'        	=> \$o_help,
        'H:s'   => \$o_host,		'hostname:s'	=> \$o_host,
        'p:i'   => \$o_port,   		'port:i'	=> \$o_port,
        'i'   => \$o_insensitive, 	'insensitive'	=> \$o_insensitive,
        'o'   => \$o_onlymatch, 	'onlymatch'	=> \$o_onlymatch,
        'a:s'   => \$o_bca,   		'bca:s'		=> \$o_bca,
        'n:s'   => \$o_bcn,   		'bcn:s'		=> \$o_bcn,
        'C:s'   => \$o_community,	'community:s'	=> \$o_community,
	'2'	=> \$o_version2,	'v2c'		=> \$o_version2,		
	'l:s'	=> \$o_login,		'login:s'	=> \$o_login,
	'x:s'	=> \$o_passwd,		'passwd:s'	=> \$o_passwd,
	'X:s'	=> \$o_privpass,	'privpass:s'	=> \$o_privpass,
	'L:s'	=> \$v3protocols,	'protocols:s'	=> \$v3protocols,   
        't:i'   => \$o_timeout,    	'timeout:i'	=> \$o_timeout,
	'r'	=> \$o_noreg,		'noregexp'	=> \$o_noreg,
	'V'	=> \$o_version,		'version'	=> \$o_version,
    );
    if (defined ($o_help) ) { help(); exit $ERRORS{"UNKNOWN"}};
    if (defined($o_version)) { p_version(); exit $ERRORS{"UNKNOWN"}};
    # check snmp information
    if ( !defined($o_community) && (!defined($o_login) || !defined($o_passwd)) )
	{ print "Put snmp login info!\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	if ((defined($o_login) || defined($o_passwd)) && (defined($o_community) || defined($o_version2)) )
	{ print "Can't mix snmp v1,2c,3 protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	if (defined ($v3protocols)) {
	  if (!defined($o_login)) { print "Put snmp V3 login info with protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	  my @v3proto=split(/,/,$v3protocols);
	  if ((defined ($v3proto[0])) && ($v3proto[0] ne "")) {$o_authproto=$v3proto[0];	}	# Auth protocol
	  if (defined ($v3proto[1])) {$o_privproto=$v3proto[1];	}	# Priv  protocol
	  if ((defined ($v3proto[1])) && (!defined($o_privpass))) {
	    print "Put snmp V3 priv login info with priv protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	}
	if (defined($o_timeout) && (isnnum($o_timeout) || ($o_timeout < 2) || ($o_timeout > 60))) 
	  { print "Timeout must be >1 and <60 !\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	if (!defined($o_timeout)) {$o_timeout=5;}
    if ( !defined($o_host) || $o_host eq ""){print "Need to specifie hostname/address\n"; exit $ERRORS{"UNKNOWN"};}

	
}
    
########## MAIN #######

check_options();

# Check gobal timeout if snmp screws up
if (defined($TIMEOUT)) {
  verb("Alarm at $TIMEOUT + 5");
  alarm($TIMEOUT+5);
} else {
  verb("no timeout defined : $o_timeout + 10");
  alarm ($o_timeout+10);
}

$SIG{'ALRM'} = sub {
 print "No answer from host\n";
 exit $ERRORS{"UNKNOWN"};
};

# Connect to host
my ($session,$error);
if ( defined($o_login) && defined($o_passwd)) {
  # SNMPv3 login
  if (!defined ($o_privpass)) {
  verb("SNMPv3 AuthNoPriv login : $o_login, $o_authproto");
    ($session, $error) = Net::SNMP->session(
      -hostname   	=> $o_host,
      -version		=> '3',
      -port      	=> $o_port,
      -username		=> $o_login,
      -authpassword	=> $o_passwd,
      -authprotocol	=> $o_authproto,
      -timeout          => $o_timeout
    );  
  } else {
    verb("SNMPv3 AuthPriv login : $o_login, $o_authproto, $o_privproto");
    ($session, $error) = Net::SNMP->session(
      -hostname   	=> $o_host,
      -version		=> '3',
      -username		=> $o_login,
      -port      	=> $o_port,
      -authpassword	=> $o_passwd,
      -authprotocol	=> $o_authproto,
      -privpassword	=> $o_privpass,
	  -privprotocol => $o_privproto,
      -timeout          => $o_timeout
    );
  }
} else {
  if (defined ($o_version2)) {
    # SNMPv2c Login
	verb("SNMP v2c login");
	($session, $error) = Net::SNMP->session(
       -hostname  => $o_host,
	   -version   => 2,
       -community => $o_community,
       -port      => $o_port,
       -timeout   => $o_timeout
    );
  } else {
    # SNMPV1 login
	verb("SNMP v1 login");
    ($session, $error) = Net::SNMP->session(
       -hostname  => $o_host,
       -community => $o_community,
       -port      => $o_port,
       -timeout   => $o_timeout
    );
  }
}
if (!defined($session)) {
   printf("ERROR opening session: %s.\n", $error);
   exit $ERRORS{"UNKNOWN"};
}

my @bca_matrix = ();
my @bcn_matrix = ();
my $resultat = undef; #Result from snmp get_table
my $output="";


sub print_array
{
	my $_string="";
	my $_arrayref = shift ;
	my @_array = @{$_arrayref};
	for (my $x = 0; $x <= $#_array; $x++) {
			$_string .=  $_array[$x] . "\t"; 
	}
	return $_string;

}

sub print_table_long
{
	my $_string="";
	my $_matrixref = shift;
	my $_labelref  = shift;
	my @_label  = @{$_labelref};
	my @_matrix = @{$_matrixref};
	if ($#_matrix >= 0)
	{
		for (my $y = 0; $y <= $#{$_matrix[0]}; $y++)
		{
			$_string.="$_label[$y]";
			if (length($_label[$y])>=8)
			{$_string.="\t";}else{$_string.="\t\t"};
			for (my $x = 0; $x<= $#_matrix ; $x++)
			{
				$_string.=$_matrix[$x][$y] . "\t";
			}
			$_string.="\n";
		}
	}
	return $_string;

}

sub print_table
{
	my $_string="";
	my $_matrixref = shift ;
	my @_matrix = @{$_matrixref};
	for (my $y = 0; $y <= $#_matrix; $y++) {
		$_string.=print_array(\@{$_matrix[$y]}) . "\n";
	}
	return $_string;

}


sub check_bca
{
	my $print_title = undef;

	$resultat = undef; #Result from snmp get_table
	$resultat = $session->get_table(
	        Baseoid => $spvBCAStateTable
	);

	if (!defined($resultat)) {
	   $output.="ERROR: BCA table : $session->error\n";
   	   edit_status(2);
	 }
	verb("Output lines number : ". scalar(keys %{$resultat}));

	foreach my $uu (keys %{$resultat}) 
	{
		verb( "$uu : $$resultat{$uu}");
		$bca_matrix[get_oid_index($uu)-1][get_oid_entry($uu)-1]=$$resultat{$uu};
	}
	
	$o_bca="" if (!defined($o_bca)); 
	for (my $ii = 0 ; $ii <= $#bca_matrix ; $ii++)
	{
		if ((defined($o_insensitive) and $bca_matrix[$ii][0] =~ m/$o_bca/i) or (!defined($o_insensitive) and $bca_matrix[$ii][0] =~ m/$o_bca/))
		{
			if (!defined($print_title))
			{
				$output.="\nBCA Table\n*********\n";
				$print_title=1;
			}
			$output.=print_array(\@{$bca_matrix[$ii]})."\n" if (defined($o_onlymatch));
			verb($bca_matrix[$ii][0] . " => status: " . $bca_matrix[$ii][1] , " " );
			edit_status($bca_matrix[$ii][1]);
		}
	}
	$output.=print_table(\@bca_matrix)  if (!defined($o_onlymatch));
	
}
sub check_bcn
{
	my $print_title = undef;

	$resultat = undef; #Result from snmp get_table
	$resultat = $session->get_table(
	        Baseoid => $spvBCNStateTable
	);

	if (!defined($resultat)) {
	   $output.="ERROR: BCN table : $session->error\n";
	   edit_status(2);
	 }
	verb("Output lines number : ". scalar(keys %{$resultat}));

	foreach my $uu (keys %{$resultat}) 
	{
		verb( "$uu : $$resultat{$uu}");
		$bcn_matrix[get_oid_index($uu)-1][get_oid_entry($uu)-1]=$$resultat{$uu};
	}
	
	$o_bcn="" if (!defined($o_bcn)); 
	for (my $ii = 0 ; $ii <= $#bcn_matrix ; $ii++)
	{
		if ((defined($o_insensitive) and $bcn_matrix[$ii][0] =~ m/$o_bcn/i) or (!defined($o_insensitive) and $bcn_matrix[$ii][0] =~ m/$o_bcn/))
		{
			if (!defined($print_title))
			{
				$output.="\nBCN Table\n*********\n";
				$print_title=1;
			}
			$output.=print_array(\@{$bcn_matrix[$ii]})."\n" if (defined($o_onlymatch));
			verb($bcn_matrix[$ii][0] . " => status: " . $bcn_matrix[$ii][3] , " " );
			edit_status($bcn_matrix[$ii][3]);
		}
	}
	$output.=print_table(\@bcn_matrix)  if (!defined($o_onlymatch));
	
}
check_bca if (defined($o_bca));
check_bcn if (defined($o_bcn));
if (!defined($o_bca) and !defined($o_bcn))
{ check_bca ; check_bcn;}

#print "BCA Table\n-------\n".print_table_long(\@bca_matrix,\@spbBCALabels)."\n\n";
#print "BcN Table\n-------\n".print_table_long(\@bcn_matrix,\@spbBCNLabels)."\n\n";

$output = $STATUS{$RET} . $output;
print $output;
# Only a few ms left...
alarm(0);

verb("Final Return : [$REVERSE_ERRORS{$RET-1}]=" . get_error_from_ret($RET));

$session->close;
exit ($RET-1);
