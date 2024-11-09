#!/bin/ksh


print "Building the man*.html index files ..."
rm -f man*.html

#  echo '<ul>' #>> new.html
  for j in *\.[0-9]*\.html
    do
    bn="$(basename $j .html)"

    sect="$(echo $j |cut -d'.' -f2-10 |tr -d '[A-Za-z.]')"

    indexfile="man${sect}.html"

    print -n "$j ($sect) "

    # get more interesting name for the link labels
    synl="$(egrep -A 2 '#toc0' $j |sed -e 's/<b>//g' -e 's/<\/b>//g' -e 's/<h2>.*//g')"
    synname="$(echo $synl |cut -d' ' -f1)"
    synopse="$(echo $synl |cut -d' ' -f3-100)"
    print
#    echo "SYNL: $synl"
#    echo "SYNNAME: $synname"
#    echo "SYNOPSE: $synopse"
    print "<li> <a href=$j>$synname</a> - $synopse" >> $indexfile
  done
#  echo '</ul>' # >> ../new.html
#  mv new.html index.html
