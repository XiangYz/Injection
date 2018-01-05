#include <iostream>
#include <Windows.h>
#include <tchar.h>


void func3()
{
	__try
	{
		*(int*)0 = 1;
	}
	__finally
	{
		std::cout << "finally" << std::endl;
		// ����������ֹȫ��չ��
		//return;  
		//goto L_FUNC3_END;
	}

L_FUNC3_END:
	return;
}


void func2()
{
	func3();
	std::cout << "func2 end" << std::endl;
}


void func()
{
	__try
	{
		func2();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		std::cout << "except" << std::endl;
	}

	std::cout << "func end" << std::endl;
}


char g_c = 0;

int filter(char** pbuf)
{
	static int cnt = 1;
	
	std::cout << cnt++ << std::endl;

	
	

	if (*pbuf == NULL)
	{
		*pbuf = &g_c;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_EXECUTE_HANDLER;
}


void f3_1(char* buf)
{
	__try
	{
		*buf = 'c';
	}
	__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? 
		EXCEPTION_CONTINUE_SEARCH : EXCEPTION_EXECUTE_HANDLER)
	{

	}
}


void f3()
{
	char* buf = NULL;

	__try
	{
		f3_1(buf);
	}
	__except (filter(&buf))
	{
		std::cout << "f3: except" << std::endl;
	}
}




int _tmain(int argc, TCHAR* argv[])
{
	char* buf = NULL;
	EXCEPTION_RECORD er;
	CONTEXT ctx;
	int x = 5, y = 0;
	__try
	{
		*buf = 'c';
		int a = 0;
		int b = 5 / a;
	}
	__except (
		// ��������������������У���Ϊ�������ṹ�嶼��ջ��
		er = *((EXCEPTION_POINTERS*)GetExceptionInformation())->ExceptionRecord,
		ctx = *((EXCEPTION_POINTERS*)GetExceptionInformation())->ContextRecord,
		//x / y, // ����˵�����쳣Ƕ��ô��Ϊɶ���ﲻ��
		EXCEPTION_EXECUTE_HANDLER
		)
	{
		
		std::cout << *buf << "    except" << std::endl;
	}


	//f3();
	
	//func();
	
	

	return 0;
}