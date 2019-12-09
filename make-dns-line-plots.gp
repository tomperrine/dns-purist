load "basic-settings.gp"
set terminal png font arial 14 size 1200,900 background '#FFFFFF'

set xlabel "Date"

set ylabel "Live hosts"

set key left top
set key box

###set tic scale 0
set grid ytics

##set xtics nomirror rotate by -90

set xdata time
set timefmt "%Y%m%d"

set output "dns-health.png"

set title "DNS errors"

set datafile separator ","

plot 'DNS-data/dns-master-auto.csv' using 1:7 title col with linespoints linecolor "navy", \
     '' using 1:8 title col with linespoints linecolor "dark-spring-green", \
     '' using 1:9 title col with linespoints linecolor "royalblue", \
