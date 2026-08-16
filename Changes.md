Picking up this project after a long time and last time i took help of AI to implement some functions and hence coming to this ... this time i am trying to own this whole application with better abstraction and understanding concepts like websockets and any other thing i took help of AI for whilst also improving the overall functioning without changing the whole Idea f Minimal IDS 

1. For Persistence switch to DB based storage.... even though this was making my Minimal-IDS very lightweight... but identifying the persistence problem while trying to use this for truly large applications i am going to change how data should be stored and what should be it's scope... so to handle the case of db crashing and providing durability
while keeping what should be ephemeral or some that should be cached

2. Right now there are 2 instances where code is clearing request log of a user for before 10s in middleware as well as the request rate detector.... need to remove one to avoid wasting resources

3. Need to Seperate Model from data schemas... to have proper categorization before i add more and more technology and end up with way too big sphaggeti code

4. Improving Detector logic and Trying to cook up some more detectors.... while first figuring out false positives and false negatives and identifying trivial evasion techniques.... while still sticking to original philosphy

5. will try to understand how i can connect this IDS to any existing service using my URL_shortener later

6. Rework/Redesign Authentication and Authorization after evaluating if it's actually secure or not and considering my other options

7. Understand and own frontend to backend communication to have better stats on dashboard

8. Learn and implement Unit Testing to test every detector in real life situations and answer request/sec, detection latency, memory usage, CPU usage, False-Positive rate, False-negative Rate