NAME = ft_ping

CC = clang
CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wshadow

SRCDIR = src
OBJDIR = obj
CFILES = main.c
HFILES =
SRC = $(addprefix $(SRCDIR)/, $(CFILES))
INC = $(addprefix $(SRCDIR)/, $(HFILES))
OBJ = $(addprefix $(OBJDIR)/, $(CFILES:.c=.o))

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

all: $(NAME)

run: all
	@./$(NAME)

$(NAME): $(OBJDIR) $(OBJ)
	$(CC) $(OBJ) -o $(NAME)

$(OBJDIR):
	mkdir -p $(OBJDIR)

debug: CFLAGS += -g
debug: all

release: CFLAGS += -flto -O3
release: all

fmt:
	@clang-format -i $(SRC) $(INC)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME) $(LINK)

re: fclean all

.PHONY: all clean fclean re release debug run
