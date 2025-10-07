# The Beacon Trail 2

## Write-up

There is four flashing pillars when going forward then left.

The first one is encoded in morse and decode to `its-a-story-about-periodicity-and-tables-and-ignoring-existing-characters`. The second one is encoded in binary and decode to `where___are_low_and_?_reach_high`. The third one is encoded in binary and decode to `flag-(?_??i__?-?__???)`. The fourth one is encoded in binary and decode to `6-2-25-16-22-1-2-44-110`.

The first text has two hints :
- You should use a periodic table
- There are existing characters somewhere and, related to these characters, you need to ignore something

The second text tells us that `_` should be lower case and `?` should be upper case.

The third text is the pattern of the flag and the fourth text is a sequence of number corresponding to elements in the periodic table.

The elements, concatenated, are `chemnstihheruds` which is the same length as the flag pattern (the thing between the ()). The second hint of the first text means to use the characters in the pattern if they are not `_` or `?`. After following the recipe, you get the flag - which is a scuff way of saying `Chemistry is hard`.

## Flag

`flag-ChEMistI-HerUDS`