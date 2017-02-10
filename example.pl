#!/usr/bin/perl

use FindBin;
use lib "$FindBin::Bin";

use Sys::Hostname;
use Stanford::DNS;
use Stanford::DNSserver;

$ns = new
  Stanford::DNSserver (
#		       listen_on => ["localhost"],
#		       listen_on => ["127.0.0.1"],
#		       port      =>          5300,
		       defttl    =>            60,
		       debug     =>             1,
		       daemon    =>          "yes",
		       pidfile   => "example.pid",

#		       chroot    =>    "/var/tmp",
#		       run_as    =>      "nobody",

		       logfunc   => sub { print shift,"\n"                },
		       loopfunc  => sub { print "weeeee ... ", `date`     },
		       exitfunc  => sub { print "good-bye cruel world!\n" }
		      );

$ns->add_static("my.net",      T_SOA, rr_SOA(hostname(), "hostmaster.my.net",
                                             time, 3600, 3600, 86400, 0));

$ns->add_static("foo.bar.net", T_SOA, rr_SOA(hostname(), "hostmaster.my.net",
                                             time, 3600, 3600, 86400, 0));

$ns->add_dynamic("echo.my.com"     => \&handle_echo_request);
$ns->add_dynamic("residual.my.net" => \&handle_residual_request);
$ns->add_dynamic("date.my.net"     => \&handle_date_request);
$ns->add_dynamic("passwd.my.net"   => \&handle_passwd_request);
$ns->add_dynamic("foo.bar.net"     => \&handle_foo_request);
$ns->add_dynamic("" => \&query_other);


$ns->answer_queries();

sub query_squire {


    my ($domain, $residual, $qtype, $qclass, $dm) = @_;

    #open STDOUT, ">>/home/sms/Logs/hlr.log" or die "Can't write to patch.log: $!";
    #open STDERR, ">>/home/sms/Logs/hlr.err" or die "Can't write to patch.err: $!";
    #$|=1;

    my $username = "$residual" . "." . "$domain";
    $username =~ s/.*e164enum.//;
    chop($username);
    print "Username je: $username \n";


    my $number = "$residual" . "." . "$domain";
    $number =~ s/\.//gi;
    $number =~ s/e164enum.*//; 
    $number = reverse $number;
    print "Checking Number: $number\n";
    my $qnumb = $number;

 if      ($qtype == 16){
                             $dm->{answer} .= dns_answer(QPTR,T_TXT,C_IN,60,rr_TXT("result:ok/mcc:$mcc_part/mnc:$mnc_part/imsi:local/msc:local/price:$price"));
 } elsif ($qtype == 35) {
                             $dm->{answer} .= dns_answer(QPTR,T_NAPTR,C_IN,60,rr_NAPTR("$mcc_part","$mnc_part"));
 }

 $dm->{ancount} += 1;

}




sub handle_echo_request {
    my ($domain, $residual, $qtype, $qclass, $dm) = @_;
    $dm->{answer} .= dns_answer(QPTR,T_TXT,C_IN,60,rr_TXT("$residual.$domain"));
    $dm->{ancount} += 1;
}

sub handle_residual_request {
    my ($domain, $residual, $qtype, $qclass, $dm) = @_;
    $dm->{answer} .= dns_answer(QPTR, T_TXT, C_IN, 60, rr_TXT($residual));
    $dm->{ancount} += 1;
}

sub handle_date_request {
    my ($domain, $residual, $qtype, $qclass, $dm) = @_;
    my ($date);

    chomp($date = `date`);

    $dm->{'answer'}  .= dns_answer(QPTR, T_TXT, C_IN, 60, rr_TXT($date));
    $dm->{'ancount'} += 1;
}

sub handle_passwd_request {
    my ($domain, $residual, $qtype, $qclass, $dm) = @_;

    my $field = '';
    if ($residual =~ /\./) {
        ($field, $residual) = $residual =~ /([^.]*)\.(.*)/;
    }

    my ($name,$passwd,$uid,$gid,$q,$c,$gcos,$dir,$shell) = getpwnam($residual);
    if ($name) {
        my $entry;
        if ($field) {
            if    ($field eq 'name'  ) { $entry = $name  }
            elsif ($field eq 'uid'   ) { $entry = $uid   }
            elsif ($field eq 'gid'   ) { $entry = $gid   }
            elsif ($field eq 'gcos'  ) { $entry = $gcos  }
            elsif ($field eq 'dir'   ) { $entry = $dir   }
            elsif ($field eq 'shell' ) { $entry = $shell }
            else  {  $dm->{rcode} = NXDOMAIN;  return 1  }
        } else {
            $entry = "$name:*:$uid:$gid:$gcos:$dir:$shell";
        }
        if ($qtype == T_TXT) {
            $dm->{answer} .= dns_answer(QPTR, T_TXT, C_IN, 60, rr_TXT($entry));
            $dm->{ancount} += 1;
        }
    } else {
        $dm->{rcode} = NXDOMAIN;
    }
}

sub handle_foo_request {
    my ($domain, $residual, $qtype, $qclass, $dm) = @_;

    my @names = qw( date fortune ps who );

    if ( not grep(/^$residual$/,@names) ) {  # does the name exist?
        $dm->{'rcode'} = NXDOMAIN;
    } elsif ($qtype != T_TXT) {              # only TXT RR's here
        $dm->{'rcode'} = NOERROR;
    } else {                                 # we know the answer!
        my $data;
        if ($residual eq "date") {
            chop( $data = `/bin/date` );
        } elsif ($residual eq "fortune") {
            chop( $data = `/usr/local/bin/fortune` );
        } elsif ($residual eq "ps") {
            $data = `/bin/ps ax`;
        } elsif ($residual eq "who") {
            $data = `/usr/bin/who`;
        }
        $dm->{'answer'}  .= dns_answer(QPTR, T_TXT, C_IN, 1, rr_TXT($data));
        $dm->{'ancount'} += 1;
    }
}
