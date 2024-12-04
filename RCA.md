# Root Cause Analysis and Solution Proposal: Authentication Microservice

## Assumptions for the Assessment

1. Since `time.Sleep(200 * time.Millisecond)` simulates processing delay,it is assumed that sleep not a production bottleneck.
2. The authentication service is hosted in AWS behind an ALB (Application Load Balancer) with the default idle timeout of 60 seconds.
3. Only a single pod of the auth service is running, as the requirement does not specify how many instances of the service we're running.

## Incident Overview

### Issue Description

The authentication microservice intermittently returns timeouts during peak usage. Users report login failures during high traffic, leading to increased dissatisfaction and support tickets.

### Key Metrics and Observations

1. **User Impact**:
   - Users face frequent errors during login attempts, especially during high traffic.
   - Users face frequent high loading screens during login attempts, especially during high traffic.
2. **Logs**:
   - Logs consistently show high request processing times, way over the p95 value of the previous hour before traffic spike.
   - Multiple Unauthorized errors due to failed login attempts.
3. **Performance Metrics**:
   - Increased 504 Gateway Timeout errors observed at the ALB when response time is > 60 seconds
   - Increased response times (p95, and significantly higher p99) at server level during peak loads.

---

## Root Cause Analysis

### 5 Whys Analysis

1. **Why are users experiencing errors?**
   - During high load, some requests to the `/login` endpoint have a `higher` response time than the ALB's configured `idle timeout`, so load balancer `establishes a connection` to the target(in this case, auth service), but `target doesn't respond back` within the `idle timeout`, so ALB sends `504 status code` to the caller, and caller (Frontend) renders error based on `>= 500` status code.
2. **Why are requests slow during peak usage?**
   - Auth service sequentially handles request processing due to `sync.Mutex` on the `userData` map, which causes blocking when there are simultaneous requests. A single request `blocks a memory address while reading the data, and unblocks at the end of authenticate function`, all other requests that land within the same time-frame, get queued and wait for the previous request to release the lock so they can read the data, this overtime piles up when the request throughput is high, causing the subsequent requests to slow down and causing 504 at alb level.
3. **Why is sequential processing used for all operations?**
   - The `sync.Mutex` ensures thread safety but ends up queueing all subsequent requests.
4. **Why does contention occur for read-heavy operations?**
   - The `sync.Mutex` locks all access to `userData`, even for `reads`, limiting performance during high loads.
5. **Why was the design not optimized for concurrency?**
   - The original implementation was likely tested under moderate load, where contention and latency were not apparent. High traffic scenarios were not simulated during testing, leaving this bottleneck unaddressed until it was encountered in production.

### Root Causes

1. **Mutex Usage**:
   - Use of `sync.Mutex` and locking the `userData` map using `mutex.Lock()` enforces sequential data reads, which can significantly bottleneck during high traffic.
2. **Usage of `fmt.Fprintf`**:
   - fmt.Fprint is formatting the arguments provided first in a buffer before calling `w.Write`, so it's not performant. Since, the `lock is not released` till the `end of the function execution`, `extra time taken by fprint` also will `hold the lock` for that `extra duration`.
3. **Late lock release**:
   - The `lock` is released using `defer`, so every line of code `after lock` is taken will be `executed before the lock is released`, which is not desired and will add to the latency.
4. **Lack of Caching**:
   - User data is accessed very frequently and instead of always accessing the `central storage`, there should be `cache` to reduce the response time.
5. **Rate limiting**:
   - There is no rate limiting in place, so crawlers or malicious users can make multiple calls to the service for no specific benefit of theirs which can be easily avoided if we have rate limits at the username and/or ip level.
6. **Only a single instance is serving all the traffic**:
   - Only a single instance of the application is running in prod, that is serving all the traffic, during peak load, the server gets overburdened.

---

## Solution Proposal

### Short-Term Mitigations

1. **Enable Concurrent Reads**:

   - Replace `sync.Mutex` with `sync.RWMutex` to allow concurrent reads while maintaining thread-safe writes.
     ```go
     var rwMutex sync.RWMutex
     rwMutex.RLock()
     password, exists := userData[user.Username]
     rwMutex.RUnlock()
     ```

2. **Minimize Lock Scope**:

   - Release locks immediately by avoiding `defer` for critical sections.
     ```go
     rwMutex.RLock()
     password, exists := userData[user.Username]
     rwMutex.RUnlock()
     ```

3. **Optimize Response Writing**:

   - `fmt.Fprintf` should be removed in favor of `w.Write` that will write directly to ResponseWriter which will be way faster as no string parsing is involved.

4. **Channel-Based Concurrency**:
   - Use channels to process requests asynchronously using a background worker, reducing contention.

---

### Long-Term Improvements

1. **Introduce Caching**:

   - Use an in-memory cache like Redis for frequently accessed data.
     ```go
     password, err := redisClient.Get(user.Username).Result()
     if err == redis.Nil {
         password, exists := userData[user.Username]
         redisClient.Set(user.Username, password, 10*time.Minute)
     }
     ```

2. **Rate Limiting**:

   - Implement rate limiting per username and/or IP to prevent abuse.

3. **Scale Horizontally**:

   - Scale horizontally by deploying multiple instances of the microservice behind the load balancer to ensure during high traffic, instead of a single pod receiving all the requests, the requests gets evenly distributed between multiple pods to avoid overburdening of a single server.

---

## Preventive Measures

1. **Load Testing**:

   - Thorough load testing with help of tools like locust, to detect these problems in advance so production doesn’t get hampered.

2. **Monitoring and Alerting**:

   - Implement tools like Prometheus, Grafana to monitor and trace performance.
   - APM like datadog or newrelic can always benefit in these scenarios by tracing the duration of each function call and point us to the exact issue.

3. **Structured Logging**:

   - Use JSON-based structured logging with unique request IDs per request for better traceability. (For simplicity, X-Amzn-Trace-Id can also be used.)

4. **Continuous Scalability Reviews**:
   - Based on traffic, the service will need architecture review to ensure the service is up to date according to the current needs.

---

### Proposed Code Example: Channel-Based Concurrency and faster alternative to `Fprintf`

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserDataRequest struct {
	Username string
	Reply    chan string
}

var (
	userData = map[string]string{
		"user1": "password1",
		"user2": "password2",
	}
	userDataChannel = make(chan UserDataRequest)
)

func userReqProcessor() {
	for req := range userDataChannel {
		userPwd, ok := userData[req.Username]
		if ok {
			req.Reply <- userPwd
		} else {
			req.Reply <- ""
		}
	}
}

func authenticate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		if duration > 300*time.Millisecond {
			log.Printf("Request processed in %s\n", duration)
		}
	}()

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	time.Sleep(200 * time.Millisecond) // Simulate processing delay

	replyChannel := make(chan string)
	userDataChannel <- UserDataRequest{
		Username: user.Username,
		Reply:    replyChannel,
	}

	storedPassword := <-replyChannel
	if storedPassword == "" || storedPassword != user.Password {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Welcome " + user.Username + "!"))
}

func main() {
	go userReqProcessor()

	http.HandleFunc("/login", authenticate)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## Conclusion

The authentication microservice failed under high load due to a combination of sequential processing, late release of lock, lack of caching and using un-performant way of response formatting and writing. Implementing concurrency optimizations by using channels or RWMutex, adding caching, and scaling by having multiple pods will address the issue and prevent similar incidents in the future.
