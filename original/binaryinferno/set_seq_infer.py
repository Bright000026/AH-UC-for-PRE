

from sumeng_module import sumeng
from Sigma import ascii2sigma,intmsgs,hexmsgs,msgs,SIGMA,FIELD,INTERVAL,apply
from deconflict import deconflict
from Weights import WCAT1,WCAT2,WCAT3

d1 = """
?
--
00000012 0000 05d6 0004 7465 7374 0a6b 6b62 2d75 6275 6e74 7500
0000001e000009f9030474657374175468697320697320612074657374206d65737361676521
00000017 0000 0757 0304 7465 7374 1048 656c 6c6f 202d 2074 6573 7469 6e67 21
00000015 0000 068d 0213 4927 6d20 676f 696e 6720 6177 6179 206e 6f77 21
--"""

foo = """
Motivation:

An IP address should never start with 0
An IP Address should never end with 0
First Octet should be below 240"""



def H(xs_):

    from collections import Counter
    import math

    # Convert our input list to strings. This lets the counter handle weird data types like lists or bytes
    xs = [str(x) for x in xs_] 

    # Count things up
    qty = Counter(xs)

    # How many things do we have?
    n = len(xs)*1.0

    # This is what we will add the summation to
    tot = 0.0

    # For item in the counter
    for item in qty:
        # Get our quantity
        v = qty[item]*1.0

        # Convert that to a probability
        p =(v/n)

        assert(p<=1) #Can't have probability greater than 1 

        # If our probability is greater than zero:
        if p>=0:
            # Add to the total 
            tot += (p * math.log(p,2))
    return abs(-tot)




def add_forward(bs):
    if (H(bs)<2 or len(set(bs)) < 5) and len(set(bs)) != 1:
        return True
    else:
        return False
    
def add_forward_BE(bs):
    if (H(bs)<2 or len(set(bs)) < 5) and len(set(bs)) != 1 and bs != [b'\x00' for i in bs]:
        #if bs != [b'\x00' for i in bs]:
          return True
    else:
        return False
         




def infer_id(txt,valuescale,LE=True):
    if type(txt) == str:
        xs = intmsgs(txt)
    else:
        xs = txt
    n = len(xs)
    if n == 1:
        return SIGMA([])


    lens = [len(x) for x in xs]
    mml = min(lens)
    max_k = mml-1
    if LE:
        endian = "LE"
    else:
        endian = "BE"
    sigmas = []
    i=0
    while i < max_k:
    #for i in range(0,max_k):
        ys = [x[i] for x in xs] #type(x[i]) == int
        #zs = [x[i+1] for x in xs]
        if len(set(ys)) == 1:
            #now all ys is the same, we need to pick out the intervals which are are the same as fields
            #detect whether the same byte could extend?
            if (max_k-i)//2 > 1: 
                for stopflag in range(1,(max_k-i)//2):
                    ys_extend = [x[i+stopflag] for x in xs]
                    if len(set(ys_extend)) != 1:
                        break
            else:
                stopflag = 1
            #if int(xs[0][i+stopflag],16) == 0 and i!=0:
            
            if int.from_bytes(xs[0][i:i+stopflag],byteorder='big') == 0 and i!=0:
                if endian == "LE":
                    #bs = [x[i-1] for x in xs]
                    #if endian == LE, we need the 0 to attach the previous offset, so i-1
                    forward_pos = i-1
                    bs = [x[forward_pos] for x in xs]
                    while add_forward(bs):
                         #if success, continue to find more previous offset
                         forward_pos -= 1
                         if forward_pos < 0:
                            break
                         bs = [x[forward_pos] for x in xs]
                         #print(forward_pos)
                    if forward_pos != i-1:
                      intervals = [INTERVAL("X",forward_pos+1,i+stopflag) for x in xs]
                      s = SIGMA([FIELD(intervals,annotation=endian + " X id sth.+00 " +str(i*8),valuescale=valuescale)])
                      sigmas.append(s)
                      i += stopflag
                      continue
                if endian == "BE":
                    #bs = [x[i-1] for x in xs]
                    #if endian == LE, we need the 0 to attach the previous offset, so i-1
                    latter_pos = i+stopflag+1
                    if latter_pos < max_k - 1:
                      bs = [x[latter_pos] for x in xs]
                      while  add_forward_BE(bs):
                           #if success, continue to find more previous offset
                           latter_pos += 1
                           if latter_pos > i+stopflag+3:
                            
                              break
                           bs = [x[latter_pos] for x in xs]
                           #print(forward_pos)
                      if latter_pos != i+stopflag+1:
                        intervals = [INTERVAL("X",i,latter_pos-1) for x in xs]
                        s = SIGMA([FIELD(intervals,annotation=endian + " X id sth.+00 " +str(i*8),valuescale=valuescale)])
                        sigmas.append(s)
                        i += stopflag + latter_pos - 1
                        continue
            #intervals = [INTERVAL("A",i,i+stopflag) for x in xs]
            #s = SIGMA([FIELD(intervals,annotation= endian + " Constant " +str(i*8),valuescale=valuescale)])
            #sigmas.append(s)
            #print("seq____ ", s)
            i += stopflag
            continue
        i+=1
        
    
    if len(sigmas) >= 1:
        print("seq__________", sigmas)
        return sigmas
    else:
        return SIGMA([])


def inferidLE(txt,valuescale=WCAT3):
    return infer_id(txt,valuescale=WCAT3)

def inferidBE(txt,valuescale=WCAT3):
    return infer_id(txt,valuescale=WCAT3,LE=False)

