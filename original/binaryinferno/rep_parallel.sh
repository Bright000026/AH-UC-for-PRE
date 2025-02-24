


cat - > tmp_par.txt
mml=$1
endianess=$2
mml=`cat tmp_par.txt | python3 Stats.py | tail -1`
echo "MML $mml"

step=1
#mml=20
echo "$mml"
result =  `python3 gen_sequence.py 0 "$mml" "$step" |parallel --jobs 30 --joblog joblog.txt "cat tmp_par.txt | python3 trimbytes.py {} | timeout 20s python3 rep_parallel.py --push {} --offset 0 --shortcircuit 1 -e $endianess " >log.txt` #--shortcircuit 50"`

#result = `python3 gen_sequence.py 0 "$mml" "$step" | cat tmp_par.txt | python3 trimbytes.py {} | timeout 20s python3 rep_parallel.py --push {} --offset 0 --shortcircuit 1 -e $endianess  > log.txt`




#cat log.txt



