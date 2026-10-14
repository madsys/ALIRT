#!/usr/bin/perl -w

use strict;

my $base_addr;
my $dis_size;
my $symbol_file;
my $base64;
my $file_tmp;
my $os_ver;
my $output;

open (FH, "./dump.info") || die "can't find dump.info. \033[;31;1mplease dump module first [modumper]\033[m\n";
while(<FH>){
	chomp;
	$base_addr = $1 if(/mod->module_core = (.*)/);
	$dis_size = $1  if(/mod->core_text_size = (.*)/);
}
close FH;
$os_ver = `uname -r`;
chomp $os_ver;
while(</boot/System.map*>){
	chomp;
	print $_ . "\n";
	$file_tmp = $_;
	if($_ eq "/boot/System.map"){
		$symbol_file = $_;
		last;
	}elsif($_ eq ("/boot/System.map-" . $os_ver)){
		$symbol_file = $_;
		last;
	}
}
$symbol_file = $file_tmp if($symbol_file eq "");
$output = `./dismod -s $base_addr -l $dis_size -t $symbol_file`;
print $output;
