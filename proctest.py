from multiprocessing import Process, Value, Array, Lock, Queue
import os
import time


def start(number,lock):
    time.sleep(1)
    with lock:
        number.value += 1
        print(number.value)

if __name__ == "__main__":    
    processes = []
    shared_value = Value('i', 0)
    lock = Lock()
    
    for i in range(os.cpu_count()):
        print("starting process: %d" % i)
        processes.append(Process(target=start, args=(shared_value,lock)))
        
    for process in processes:
        process.start()
        
    for process in processes:
        process.join()
        
    print('endresult: ', shared_value.value)