To add the test "alarm-mega.ck" I first copied "alarm-multiple.ck" and changed "check_alarm (7);" to "check_alarm (100);".

Next I modified "tests.c" by adding "alarm-mega" to the struct and I added "test_alarm_mega" to tests.h

Then I added 
	void
	test_alarm_mega(void)
	{
	  test_sleep(5,100);
	}
to "alarm-wait.c".

Finally I rebuilt and ran the test
