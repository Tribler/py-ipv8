library(ggplot2)

bootstrap_introductions <- read.table("bootstrap_introductions.txt", header=T, quote="\"")
p <- ggplot(data=bootstrap_introductions, aes(x=Address, y=Peers, fill=factor(Type))) +
  geom_bar(position=position_dodge2(reverse=TRUE, width=0.8), width=0.7, stat="identity") +
  coord_flip() + 
  ggtitle("Number of addresses discovered while bootstrapping") + 
  scale_x_discrete(limits=rev(sort(unique(bootstrap_introductions$Address)))) +
  scale_fill_discrete(labels=c("Total WAN addresses", "Unique WAN addresses", "Reachable WAN addresses", "Total LAN addresses")) +
  theme(legend.title=element_blank())
p
ggsave("bootstrap_introductions.png", width=10, height=6, dpi=100)
q(save="no")
