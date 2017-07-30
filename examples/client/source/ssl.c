#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <3ds.h>
#include <wslay/wslay.h>
#include <wslay/ctr.h>
#include <malloc.h>

void on_recv_msg(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data)
{
	char *s = malloc(arg->msg_length + 1);
	memcpy(s, arg->msg, arg->msg_length);
	s[arg->msg_length] = 0;
	printf("Opcode %02x, msg %s!!\n", arg->opcode, s);
	free(s);
}

int main()
{
	Result ret=0;
	u32 *soc_sharedmem, soc_sharedmem_size = 0x100000;

	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	printf("wslay demo.\n");

	soc_sharedmem = memalign(0x1000, soc_sharedmem_size);
	if(soc_sharedmem==NULL)
	{
		printf("Failed to allocate SOC sharedmem.\n");
	}
	else
	{
		ret = socInit(soc_sharedmem, soc_sharedmem_size);

		if(R_FAILED(ret))
		{
			printf("socInit failed: 0x%08x.\n", (unsigned int)ret);
		}
		else
		{
			ret = sslcInit(0);
			if(R_FAILED(ret))
			{
				printf("sslcInit failed: 0x%08x.\n", (unsigned int)ret);
			}
			else
			{
				struct wslay_ctr_ctx ctx;
				struct wslay_event_callbacks cb;
				memset(&cb, 0, sizeof(struct wslay_event_callbacks));
				
				cb.on_msg_recv_callback = on_recv_msg;
				ret = wslay_ctr_client_init("172.31.1.200", 8080, &ctx, &cb);
				if(R_FAILED(ret))
				{
					printf("wslay_ctr_client_init failed: 0x%08x.\n", (unsigned int)ret);
				}
				else
				{
					ret = wslay_ctr_client_connect(&ctx);
					if(R_FAILED(ret))
					{
						printf("wslay_ctr_client_connect failed: 0x%08x.\n", (unsigned int)ret);
					}
					else
					{
						printf("k?\n");
						wslay_ctr_client_run(&ctx);
					}
				}
				

				sslcExit();
			}

			socExit();
		}
	}

	printf("Press START to exit.\n");

	// Main loop
	while (aptMainLoop())
	{
		gspWaitForVBlank();
		hidScanInput();

		u32 kDown = hidKeysDown();
		if (kDown & KEY_START)
			break; // break in order to return to hbmenu

		// Flush and swap framebuffers
		gfxFlushBuffers();
		gfxSwapBuffers();
	}

	gfxExit();
	return 0;
}
