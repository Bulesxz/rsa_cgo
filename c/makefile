.PHONY: clean

TARGET=librsa.a
HEADER_PATH  = -I/usr/local/Cellar/openssl@1.1/1.1.0f/include

$(TARGET): rsa.o
	ar r $@ $^	
%.o: %.cpp
	$(CC)  -o $@ -c $^ $(HEADER_PATH)

clean:
	rm -f *.o *.so *.a $(TARGET)
