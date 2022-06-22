/* gcc -fpie -pie -z now -o summoner summoner.c */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
  
struct creature {
    char *name;
    int level;
};

void intro()
{
    puts("After you climb over the snow mountain, you encounter an evil summoner!\n");
    puts("He summoned \"The Dark Lord\" Level 5! You have to get over his dead body to fight the Demon Dragon, but you can only summon Level 4 creatures!\n");
    puts("What's your plan for now???\n");
}

void menu()
{
    puts("Available plans:");
    puts("\tshow - show your creature and its level");
    puts("\tsummon [name] - summon a creature called [name]");
    puts("\tlevel-up [level] - level up your creature (below Level 5)");
    puts("\tstrike - STRIKE the evil summoner's creature!!!");
    puts("\trelease - release your creature");
    puts("\tquit - give up and die");
}

int main(int argc, char **argv)
{
    char buf[0x200];
    char *arg;
    uint32_t level;
    struct creature *c;

    setbuf(stdout, NULL);
    intro();
    menu();
    c = NULL;
    while(1) {
        printf("\nEnter your command:\n> ");

        if(fgets(buf, 0x200, stdin) == NULL)
            break;

        if (!strncmp(buf, "show", 4)) {
            if(c == NULL)
	            puts("You have no creature now.");
            else
	            printf("Current creature: %s [Level %u]\n", c->name, c->level);
        } else if (!strncmp(buf, "summon", 6)) {
            if (c != NULL) {
	            puts("Already have one creature. Release it first.");
	            continue;
            }
            arg = strtok(&buf[7], "\n");
            if (arg == NULL) {
	            puts("Invalid command");
	            continue;
            }
            c = (struct creature *)malloc(sizeof(struct creature));
            if (c == NULL) {
	            puts("malloc() returned NULL. Out of Memory\n");
	            exit(-1);
            }
            c->name = strdup(arg);
            printf("Current creature:\"%s\"\n", arg);
        } else if(!strncmp(buf, "level-up", 8)) {
            if(c == NULL) {
	            puts("Summon first.");
	            continue;
            }
            arg = strtok(&buf[9], "\n");
            if (arg == NULL) {
	            puts("Invalid command");
	            continue;
            }
            level = strtoul(arg, NULL, 10);
            if (level >= 5) {
	            puts("Can only level-up to Level 4.");
	            continue;
            }
            c->level = level;
            printf("Level-up to \"%u\"\n", level);
        } else if(!strncmp(buf, "strike", 6)) {
            if (c == NULL) {
	            puts("Summon first.");
	            continue;
            }
            if (c->level != 5) {
	            puts("No, you cannot beat him!");
	            continue;
            }
            system("/bin/cat /pwn/flag");
        } else if(!strncmp(buf, "release", 7)) {
            if (c == NULL){
	            puts("No creature summoned.");
	            continue;
            }
            free(c->name);
            c = NULL;
            puts("Released.");
        } else if(!strncmp(buf, "quit", 4)) {
            return 0;
        } else {
            puts("Invalid option");
            menu();
        }
    }
}